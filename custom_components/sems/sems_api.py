            )

            if json_response is None:
                return self.getFlow(
                    powerStationId,
                    renewToken=True,
                    maxTokenRetries=maxTokenRetries - 1,
                )

            result = json_response.get("data")
            return result if isinstance(result, dict) else {}

        except SemsRateLimitedError:
            raise
        except SemsEmptyDataError as exception:
            _LOGGER.warning(
                "SEMS - getFlow returned no usable data; waiting for the next refresh: %s",
                exception,
            )
            return {}
        except (requests.RequestException, ValueError, KeyError) as exception:
            _LOGGER.error("Unable to complete getFlow API call: %s", exception)
            return {}
            
    def _make_control_api_call(
        self,
        data: dict[str, Any],
        renewToken: bool = False,
        maxTokenRetries: int = 2,
        operation_name: str = "Control API call",
    ) -> bool:
        """Make a control API call with different response handling."""
        _LOGGER.debug("SEMS - Making %s", operation_name)
        if maxTokenRetries <= 0:
            _LOGGER.info("SEMS - Maximum token fetch tries reached, aborting for now")
            raise OutOfRetries

        context = self._get_authenticated_request_context(
            _PowerControlURLPart, renewToken, operation_name
        )
        if context is None:
            return False

        api_url, headers = context

        try:
            # Control API uses different validation (HTTP status code), so don't validate JSON response code
            self._make_http_request(
                api_url,
                headers,
                json_data=data,
                operation_name=operation_name,
                validate_code=False,
            )

            # For control API, any successful HTTP response (status 200) means success
            # The _make_http_request already validated HTTP status via raise_for_status()
            return True

        except requests.HTTPError as e:
            if hasattr(e.response, "status_code") and e.response.status_code != 200:
                _LOGGER.warning(
                    "%s not successful, retrying with new token, %s retries remaining",
                    operation_name,
                    maxTokenRetries,
                )
                return self._make_control_api_call(
                    data, True, maxTokenRetries - 1, operation_name
                )
            _LOGGER.error("Unable to execute %s: %s", operation_name, e)
            return False
        except SemsRateLimitedError as exception:
            _LOGGER.warning("Unable to execute %s: %s", operation_name, exception)
            return False
        except (requests.RequestException, ValueError, KeyError) as exception:
            _LOGGER.error("Unable to execute %s: %s", operation_name, exception)
            return False

    def change_status(
        self,
        inverterSn: str,
        status: str | int,
        renewToken: bool = False,
        maxTokenRetries: int = 2,
    ) -> None:
        """Schedule the downtime of the station."""
        data = {
            "InverterSN": inverterSn,
            "InverterStatusSettingMark": "1",
            "InverterStatus": str(status),
        }

        success = self._make_control_api_call(
            data,
            renewToken=renewToken,
            maxTokenRetries=maxTokenRetries,
            operation_name=f"power control command for inverter {inverterSn}",
        )

        if not success:
            _LOGGER.error("Power control command failed after all retries")


class OutOfRetries(exceptions.HomeAssistantError):
    """Error to indicate too many error attempts."""


class SemsEmptyDataError(exceptions.HomeAssistantError):
    """Error to indicate SEMS returned a successful response without usable data."""


class SemsRateLimitedError(exceptions.HomeAssistantError):
    """Error to indicate the SEMS API requested retry with backoff."""

    def __init__(self, retry_after: int, message: str = "SEMS API rate limited"):
        """Initialize rate limit exception."""
        super().__init__(message)
        self.retry_after = retry_after
