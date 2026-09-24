from __future__ import annotations

import base64
import hashlib
import json
import logging
from collections.abc import Callable
from typing import Any, Literal

import requests
from homeassistant import exceptions
from homeassistant.core import HomeAssistant

from .const import redact_for_log

_LOGGER = logging.getLogger(__name__)

OLD_LOGIN_URL = "https://www.semsportal.com/api/v3/Common/CrossLogin"
NEW_LOGIN_URL = "https://eu-semsplus.goodwe.com/web/sems/sems-user/api/v1/auth/cross-login"
_GetPowerStationIdByOwnerURLPart = "/PowerStation/GetPowerStationIdByOwner"
_PowerStationURLPart = "/v3/PowerStation/GetMonitorDetailByPowerstationId"
# _PowerControlURL = (
#     "https://www.semsportal.com/api/PowerStation/SaveRemoteControlInverter"
# )
_PowerControlURLPart = "/PowerStation/SaveRemoteControlInverter"
_RequestTimeout = 30  # seconds
_RateLimitRetryAfterSeconds = 300

_SuccessCodes = {0, "0", "00000"}
_RateLimitCode = "GY0429"

_DefaultHeaders = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "token": '{"version":"3.1.1","client":"ios","language":"en"}',
}

_NewLoginHeaders = {
    "Content-Type": "application/json",
    "Accept": "application/json, */*;q=0.5",
}

_NewLoginFallbackApi = "https://eu-gateway.semsportal.com/web/sems"
_LegacyApiFallback = "https://eu.semsportal.com/api"

_FlowURLPart = "/sems-plant/api/stations/flow"
_GatewayClient = "semsPlusWeb"
_SemsPlusOrigin = "https://eu-semsplus.goodwe.com"
_SemsPlusUserAgent = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)
_DefaultUserAgent = "PVMaster/2.9.5 (iPhone; iOS 17.5; Scale/3.00)"

type LoginMode = Literal["new", "legacy"]
type LoginHandler = Callable[[str, str], dict[str, Any] | None]


class SemsApi:
    """Interface to the SEMS API."""

    def __init__(self, hass: HomeAssistant, username: str, password: str) -> None:
        """Init dummy hub."""
        self._hass = hass
        self._username = username
        self._password = password
        self._token: dict[str, Any] | None = None
        self._preferred_login_mode: LoginMode | None = None

    def test_authentication(self) -> bool:
        """Test if we can authenticate with the host."""
        try:
            self._token = self.getLoginToken(self._username, self._password)
        except (AttributeError, KeyError, TypeError, ValueError) as exception:
            _LOGGER.exception("SEMS Authentication exception: %s", exception)
            return False
        else:
            return self._token is not None

    def _make_http_request(
        self,
        url: str,
        headers: dict[str, str],
        data: str | None = None,
        json_data: dict[str, Any] | None = None,
        operation_name: str = "HTTP request",
        validate_code: bool = True,
        method: Literal["GET", "POST"] = "POST",
    ) -> dict[str, Any] | None:
        """Make a generic HTTP request with error handling and optional code validation."""
        try:
            _LOGGER.debug("SEMS - Making %s to %s", operation_name, url)
            if method == "GET":
                response = requests.get(
                    url,
                    headers=headers,
                    timeout=_RequestTimeout,
                )
            else:
                response = requests.post(
                    url,
                    headers=headers,
                    data=data,
                    json=json_data,
                    timeout=_RequestTimeout,
                )

            _LOGGER.debug("%s Response: %s", operation_name, response)
            # _LOGGER.debug("%s Response text: %s", operation_name, response.text)

            response.raise_for_status()
            json_response: dict[str, Any] = response.json()
            response_code = json_response.get("code")

            if self._is_sensitive_operation(operation_name):
                _LOGGER.debug(
                    "SEMS - %s response payload: %s",
                    operation_name,
                    redact_for_log(json_response),
                )

            _LOGGER.debug(
                "SEMS - %s response summary: code=%s msg=%s description=%s api=%s has_data=%s",
                operation_name,
                response_code,
                json_response.get("msg"),
                json_response.get("description"),
                json_response.get("api"),
                json_response.get("data") not in (None, "", [], {}),
            )

            if str(response_code) == _RateLimitCode:
                raise SemsRateLimitedError(
                    retry_after=_RateLimitRetryAfterSeconds,
                    message=(
                        f"{operation_name} returned rate-limit code {_RateLimitCode}"
                    ),
                )

            # Validate response code if requested
            if validate_code:
                if response_code not in _SuccessCodes:
                    _LOGGER.error(
                        "%s failed with code: %s, message: %s",
                        operation_name,
                        response_code,
                        json_response.get("msg", "Unknown error"),
                    )
                    return None

                data = json_response.get("data")
                if data is None or data == "" or data == [] or data == {}:
                    _LOGGER.error(
                        "SEMS - %s returned success code but no usable data: "
                        "code=%s msg=%s description=%s api=%s keys=%s payload=%s",
                        operation_name,
                        response_code,
                        json_response.get("msg"),
                        json_response.get("description"),
                        json_response.get("api"),
                        list(json_response.keys()),
                        redact_for_log(json_response),
                    )
                    raise SemsEmptyDataError(
                        f"{operation_name} returned success code {response_code} without data"
                    )

            return json_response

        except requests.HTTPError as exception:
            if (response := exception.response) is not None:
                if self._is_sensitive_operation(operation_name):
                    _LOGGER.error(
                        "Unable to complete %s: status=%s url=%s (response body redacted)",
                        operation_name,
                        response.status_code,
                        response.url,
                    )
                else:
                    _LOGGER.error(
                        "Unable to complete %s: status=%s url=%s body=%s",
                        operation_name,
                        response.status_code,
                        response.url,
                        response.text,
                    )
            else:
                _LOGGER.error("Unable to complete %s: %s", operation_name, exception)
            raise
        except (requests.RequestException, ValueError, KeyError) as exception:
            _LOGGER.error("Unable to complete %s: %s", operation_name, exception)
            raise

    def _is_sensitive_operation(self, operation_name: str) -> bool:
        """Return True if the operation name indicates it handles sensitive credentials."""
        return "login" in operation_name.lower()

    def _hash_password_for_new_login(self, password: str) -> str:
        """Return the SEMS+ password encoding."""
        # MD5 is required by the SEMS+ API protocol; usedforsecurity=False avoids
        # failures on FIPS-enabled systems where MD5 is disabled for security use.
        md5_password = hashlib.md5(
            password.encode("utf-8"), usedforsecurity=False
        ).hexdigest()
        return base64.b64encode(md5_password.encode("utf-8")).decode("utf-8")

    def _is_powerstation_route(self, url_part: str) -> bool:
        """Return whether the route should use the legacy PowerStation host."""
        return url_part.startswith("/PowerStation") or url_part.startswith(
            "/v3/PowerStation"
        )

    def _extract_gateway_region(self, api_base: str) -> str | None:
        """Return the SEMS region prefix from a gateway API base."""
        host = api_base.split("//", 1)[-1].split("/", 1)[0]
        if host.endswith("-gateway.semsportal.com"):
            return host.removesuffix("-gateway.semsportal.com") or None

        if host.endswith(".semsportal.com"):
            return host.split(".", 1)[0] or None

        return None

    def _normalize_powerstation_api_base(self, api_base: str, url_part: str) -> str:
        """Return the effective API base for PowerStation requests."""
        if not self._is_powerstation_route(url_part):
            return api_base

        if "/web/sems" not in api_base and "/sems/" not in api_base:
            return api_base

        region = None
        if isinstance(self._token, dict) and isinstance(self._token.get("region"), str):
            region = self._token["region"] or None
        if region is None:
            region = self._extract_gateway_region(api_base)

        if region:
            rewritten_base = f"https://{region}.semsportal.com/api"
            _LOGGER.debug(
                "SEMS - Rewriting API base from %s to %s for %s",
                api_base,
                rewritten_base,
                url_part,
            )
            return rewritten_base

        _LOGGER.debug(
            "SEMS - Rewriting API base from %s to fallback %s for %s",
            api_base,
            _LegacyApiFallback,
            url_part,
        )
        return _LegacyApiFallback

    def _resolve_api_base_for_url_part(self, api_base: str, url_part: str) -> str:
        """Return the effective API base for a given endpoint path."""

        # SEMS+ endpoints use the regional gateway under /web/sems.
        if url_part.startswith("/sems-plant/"):
            region = None

            if isinstance(self._token, dict):
                token_region = self._token.get("region")
                if isinstance(token_region, str) and token_region:
                    region = token_region

            if region is None:
                region = self._extract_gateway_region(api_base)

            if region:
                rewritten_base = (
                    f"https://{region}-gateway.semsportal.com/web/sems"
                )
            else:
                rewritten_base = _NewLoginFallbackApi

            _LOGGER.debug(
                "SEMS - Rewriting API base from %s to %s for SEMS+ endpoint %s",
                api_base,
                rewritten_base,
                url_part,
            )

            return rewritten_base

        return self._normalize_powerstation_api_base(api_base, url_part)
    def _get_authenticated_request_context(
        self,
        url_part: str,
        renewToken: bool,
        operation_name: str,
    ) -> tuple[str, dict[str, str]] | None:
        """Return the request URL and headers for an authenticated call."""
        if self._token is None or renewToken:
            _LOGGER.debug(
                "API token not set (%s) or new token requested (%s), fetching",
                redact_for_log(self._token),
                renewToken,
            )
            self._token = self.getLoginToken(self._username, self._password)

        if self._token is None:
            _LOGGER.error("Failed to obtain API token")
            return None

        api_base = self._resolve_api_base_for_url_part(self._token["api"], url_part)
        api_url = api_base + url_part
        headers = self._build_authenticated_headers(self._token)

        _LOGGER.debug(
            "SEMS - %s request context: api_base=%s effective_api_base=%s url_part=%s token=%s",
            operation_name,
            self._token.get("api"),
            api_base,
            url_part,
            redact_for_log(self._token),
        )
        return api_url, headers

    def _gateway_signature(self, uid: str, token: str) -> str:
        """Build the x-signature required by the current SEMS+ gateway."""
        import time

        timestamp = str(int(time.time() * 1000))
        digest = hashlib.sha256(
            f"{timestamp}@{uid}@{token}".encode("utf-8")
        ).hexdigest()
        return base64.b64encode(
            f"{digest}@{timestamp}".encode("utf-8")
        ).decode("utf-8")

    def _build_gateway_headers(self) -> dict[str, str]:
        """Build headers matching the SEMS+ web/gateway client."""
        if self._token is None:
            raise ValueError("No SEMS token available")

        api_base = self._resolve_api_base_for_url_part(
            self._token["api"], "/sems-plant/"
        )
        uid = str(self._token.get("uid", ""))
        token = str(self._token.get("token", ""))

        token_payload = {
            "uid": uid,
            "timestamp": str(self._token.get("timestamp", "")),
            "token": token,
            "client": _GatewayClient,
            "version": "",
            "language": "en",
            "api": api_base,
            "region": str(self._token.get("region") or "eu"),
        }

        return {
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            "User-Agent": _DefaultUserAgent,
            "token": json.dumps(token_payload),
            "x-signature": self._gateway_signature(uid, token),
        }

    def _gateway_request(
        self,
        method: Literal["GET", "POST"],
        url_part: str,
        query: dict[str, Any] | None = None,
        renewToken: bool = False,
        maxTokenRetries: int = 2,
        operation_name: str = "gateway API call",
    ) -> Any | None:
        """Call a SEMS+ gateway endpoint with signature and one token refresh."""
        from urllib.parse import urlencode

        if maxTokenRetries <= 0:
            raise OutOfRetries

        if self._token is None or renewToken:
            self._token = self.getLoginToken(self._username, self._password)

        if self._token is None:
            _LOGGER.error("SEMS - Unable to obtain token for %s", operation_name)
            return None

        api_base = self._resolve_api_base_for_url_part(
            self._token["api"], url_part
        )
        api_url = api_base + url_part
        if query:
            api_url += "?" + urlencode(query)

        try:
            json_response = self._make_http_request(
                api_url,
                self._build_gateway_headers(),
                operation_name=operation_name,
                validate_code=False,
                method=method,
            )
            if json_response is None:
                return None

            code = json_response.get("code")
            if str(code) == _RateLimitCode:
                raise SemsRateLimitedError(
                    retry_after=_RateLimitRetryAfterSeconds,
                    message=f"{operation_name} returned rate-limit code {_RateLimitCode}",
                )

            if code not in _SuccessCodes:
                _LOGGER.warning(
                    "SEMS - %s failed: code=%s msg=%s description=%s",
                    operation_name,
                    code,
                    json_response.get("msg"),
                    json_response.get("description"),
                )
                if maxTokenRetries > 1:
                    return self._gateway_request(
                        method,
                        url_part,
                        query=query,
                        renewToken=True,
                        maxTokenRetries=maxTokenRetries - 1,
                        operation_name=operation_name,
                    )
                return None

            return json_response.get("data")

        except SemsRateLimitedError:
            raise
        except (requests.RequestException, ValueError, KeyError) as exception:
            _LOGGER.error("Unable to complete %s: %s", operation_name, exception)
            return None

    def _flatten_gateway_factors(self, groups: Any) -> dict[str, Any]:
        """Flatten SEMS+ telemetry factor groups to code -> value."""
        result: dict[str, Any] = {}
        if not isinstance(groups, list):
            return result

        for group in groups:
            if not isinstance(group, dict):
                continue
            factors = group.get("factors")
            if not isinstance(factors, list):
                factors = [group]
            for factor in factors:
                if isinstance(factor, dict) and factor.get("code") is not None:
                    result[str(factor["code"])] = factor.get("data")
        return result

    def _number(self, value: Any) -> float | None:
        """Coerce a gateway numeric value without inventing missing values."""
        if value is None or value == "":
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def _build_authenticated_headers(
        self, token_data: dict[str, Any]
    ) -> dict[str, str]:
        """Build request headers for authenticated API calls."""
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "token": json.dumps(token_data),
        }

    def _get_login_mode_order(self) -> list[LoginMode]:
        """Return login modes in preferred order."""
        login_modes: list[LoginMode] = ["new", "legacy"]
        if self._preferred_login_mode in login_modes:
            login_modes.remove(self._preferred_login_mode)
            login_modes.insert(0, self._preferred_login_mode)
        return login_modes

    def _login_handler_for_mode(self, login_mode: LoginMode) -> LoginHandler:
        """Return the login handler for a given mode."""
        if login_mode == "legacy":
            return self._get_legacy_login_token
        return self._get_new_login_token

    def _resolve_login_api_url(
        self,
        json_response: dict[str, Any],
        token_data: dict[str, Any],
        login_mode: LoginMode,
        fallback_api_url: str | None,
    ) -> str | None:
        """Resolve API URL from login response with optional fallback."""
        api_url = (
            json_response.get("api")
            if isinstance(json_response.get("api"), str)
            else token_data.get("api")
        )
        if isinstance(api_url, str) and api_url:
            return api_url

        if fallback_api_url is None:
            _LOGGER.error(
                "SEMS %s login response missing api field: keys=%s",
                login_mode,
                list(json_response.keys()),
            )
            return None

        _LOGGER.debug(
            "SEMS %s login response missing api field, falling back to %s",
            login_mode,
            fallback_api_url,
        )
        return fallback_api_url

    def _extract_login_token(
        self,
        json_response: dict[str, Any] | None,
        login_mode: LoginMode,
        operation_name: str,
        fallback_api_url: str | None = None,
    ) -> dict[str, Any] | None:
        """Normalize a login response into the token payload expected elsewhere."""
        if json_response is None:
            return None

        code = json_response.get("code")
        if code not in _SuccessCodes:
            _LOGGER.debug(
                "SEMS %s login failed during %s with code %s, msg=%s, description=%s, api=%s, data_type=%s",
                login_mode,
                operation_name,
                code,
                json_response.get("msg"),
                json_response.get("description"),
                json_response.get("api"),
                type(json_response.get("data")).__name__,
            )
            return None

        token_data = json_response.get("data")
        if not isinstance(token_data, dict) or not token_data:
            _LOGGER.error(
                "SEMS %s login response data was missing or invalid: data_type=%s, keys=%s",
                login_mode,
                type(token_data).__name__,
                list(json_response.keys()),
            )
            return None

        api_url = self._resolve_login_api_url(
            json_response,
            token_data,
            login_mode,
            fallback_api_url,
        )
        if api_url is None:
            return None

        token_dict = dict(token_data)
        token_dict["api"] = api_url

        if not token_dict.get("token"):
            _LOGGER.warning(
                "SEMS %s login response missing valid token field - incomplete token received",
                login_mode,
            )
            return None

        _LOGGER.debug(
            "SEMS - API Token received via %s login: %s",
            login_mode,
            redact_for_log(token_dict),
        )
        self._preferred_login_mode = login_mode
        return token_dict

    def _get_legacy_login_token(
        self, userName: str, password: str
    ) -> dict[str, Any] | None:
        """Get a token from the legacy SEMS login endpoint."""
        _LOGGER.debug("SEMS - Trying legacy login")
        login_data = json.dumps({"account": userName, "pwd": password})
        json_response = self._make_http_request(
            OLD_LOGIN_URL,
            _DefaultHeaders,
            data=login_data,
            operation_name="legacy login API call",
            validate_code=False,
        )
        return self._extract_login_token(
            json_response, "legacy", "legacy login API call"
        )

    def _get_new_login_token(
        self, userName: str, password: str
    ) -> dict[str, Any] | None:
        """Get a token from the SEMS+ login endpoint."""
        _LOGGER.debug("SEMS - Trying new SEMS+ login")
        login_data = {
            "account": userName,
            "pwd": self._hash_password_for_new_login(password),
            "agreement": 1,
            "isChinese": False,
            "isLocal": False,
        }
        login_token_payload = {
            "uid": "",
            "timestamp": 0,
            "token": "",
            "client": _GatewayClient,
            "version": "",
            "language": "en",
        }
        login_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            "User-Agent": _SemsPlusUserAgent,
            "Origin": _SemsPlusOrigin,
            "Referer": f"{_SemsPlusOrigin}/",
            "token": json.dumps(login_token_payload),
            "x-signature": self._gateway_signature("", ""),
        }

        json_response = self._make_http_request(
            NEW_LOGIN_URL,
            login_headers,
            json_data=login_data,
            operation_name="SEMS+ login API call",
            validate_code=False,
        )
        return self._extract_login_token(
            json_response,
            "new",
            "SEMS+ login API call",
            _NewLoginFallbackApi,
        )

    def getLoginToken(self, userName: str, password: str) -> dict[str, Any] | None:
        """Get the login token for the SEMS API."""
        try:
            for login_mode in self._get_login_mode_order():
                token = self._login_handler_for_mode(login_mode)(userName, password)

                if token is not None:
                    # Keep preferred mode in sync even when login helpers are mocked in tests.
                    self._preferred_login_mode = login_mode
                    return token

            return None

        except (requests.RequestException, ValueError, KeyError) as exception:
            _LOGGER.error("Unable to fetch login token from SEMS API: %s", exception)
            return None

    def _make_api_call(
        self,
        url_part: str,
        data: str | None = None,
        renewToken: bool = False,
        maxTokenRetries: int = 2,
        operation_name: str = "API call",
    ) -> Any | None:
        """Make a generic API call with token management and retry logic."""
        _LOGGER.debug("SEMS - Making %s", operation_name)
        if maxTokenRetries <= 0:
            _LOGGER.info("SEMS - Maximum token fetch tries reached, aborting for now")
            raise OutOfRetries

        context = self._get_authenticated_request_context(
            url_part, renewToken, operation_name
        )
        if context is None:
            return None

        api_url, headers = context

        try:
            json_response: dict[str, Any] | None = self._make_http_request(
                api_url,
                headers,
                data=data,
                operation_name=operation_name,
                validate_code=True,
            )

            # _make_http_request already validated the response, so if we get here, it's successful
            if json_response is None:
                # Response validation failed in _make_http_request
                _LOGGER.debug(
                    "%s not successful, retrying with new token, %s retries remaining",
                    operation_name,
                    maxTokenRetries,
                )
                return self._make_api_call(
                    url_part, data, True, maxTokenRetries - 1, operation_name
                )

            # Response is valid, return the data
            return json_response["data"]

        except SemsRateLimitedError as exception:
            _LOGGER.debug(
                "SEMS - Propagating rate limit from %s to coordinator: retry_after=%s",
                operation_name,
                exception.retry_after,
            )
            raise
        except SemsEmptyDataError as exception:
            # A response with a success code but without data is not normally fixed
            # by immediately logging in again. Avoid a second request every refresh
            # cycle, which can make SEMS rate limiting worse.
            _LOGGER.warning(
                "SEMS - %s returned no usable data; keeping the current token and "
                "waiting for the next coordinator refresh: %s",
                operation_name,
                exception,
            )
            return None
        except (requests.RequestException, ValueError, KeyError) as exception:
            _LOGGER.error("Unable to complete %s: %s", operation_name, exception)
            return None

    def getPowerStationIds(
        self, renewToken: bool = False, maxTokenRetries: int = 2
    ) -> Any | None:
        """Get the power station ids from the SEMS API."""
        return self._make_api_call(
            _GetPowerStationIdByOwnerURLPart,
            data=None,
            renewToken=renewToken,
            maxTokenRetries=maxTokenRetries,
            operation_name="getPowerStationIds API call",
        )

    def getData(
        self, powerStationId: str, renewToken: bool = False, maxTokenRetries: int = 2
    ) -> dict[str, Any]:
        """Get station data from the current SEMS+ gateway."""
        basic_info = self._gateway_request(
            "POST",
            "/sems-plant/api/portal/stations/basic/info",
            query={"stationId": powerStationId},
            renewToken=renewToken,
            maxTokenRetries=maxTokenRetries,
            operation_name="getData basic info API call",
        )
        if not isinstance(basic_info, dict):
            basic_info = {}

        all_status = self._gateway_request(
            "GET",
            "/sems-plant/api/stations/device/all-status",
            query={"stationId": powerStationId},
            renewToken=False,
            maxTokenRetries=maxTokenRetries,
            operation_name="getData device status API call",
        )

        devices: list[dict[str, Any]] = []
        if isinstance(all_status, dict):
            detail_lists = all_status.get("deviceDetailList", [])
            if isinstance(detail_lists, list):
                for type_group in detail_lists:
                    if not isinstance(type_group, dict):
                        continue
                    device_type = str(type_group.get("deviceType") or "INVERTER")
                    status_details = type_group.get("statusDetailList", [])
                    if not isinstance(status_details, list):
                        continue
                    for status_detail in status_details:
                        if not isinstance(status_detail, dict):
                            continue
                        detail_map = status_detail.get("detailMap", {})
                        if not isinstance(detail_map, dict):
                            continue
                        for sn, device_detail in detail_map.items():
                            detail = dict(device_detail) if isinstance(device_detail, dict) else {}
                            detail["sn"] = sn
                            detail["deviceType"] = device_type
                            devices.append(detail)

        inverters: list[dict[str, Any]] = []
        for device in devices:
            device_type = str(device.get("deviceType") or "").upper()

            # SMART_METER must not be exposed as an inverter, but log its
            # telemetry temporarily so we can identify the accumulated
            # grid import/export counters used by SEMS Total Import/Export.
            if device_type == "SMART_METER":
                meter_sn = str(device.get("sn") or "")
                if meter_sn:
                    meter_telemetry = self._gateway_request(
                        "GET",
                        f"/sems-plant/api/equipments/{meter_sn}/telemetry",
                        query={"deviceType": "SMART_METER", "pwId": powerStationId},
                        maxTokenRetries=maxTokenRetries,
                        operation_name=f"debug SMART_METER telemetry {meter_sn}",
                    )
                    meter_flat = self._flatten_gateway_factors(meter_telemetry)
                    _LOGGER.warning(
                        "SEMS - SMART_METER FACTORS %s: %s",
                        redact_for_log(meter_sn),
                        meter_flat,
                    )
                continue

            if device_type != "INVERTER":
                _LOGGER.debug(
                    "SEMS - Skipping non-inverter device %s type=%s",
                    redact_for_log(device.get("sn")),
                    device_type,
                )
                continue

            sn = str(device.get("sn") or "")
            if not sn:
                continue

            telemetry = self._gateway_request(
                "GET",
                f"/sems-plant/api/equipments/{sn}/telemetry",
                query={"deviceType": "INVERTER", "pwId": powerStationId},
                maxTokenRetries=maxTokenRetries,
                operation_name=f"getData telemetry {sn}",
            )
            telecounting = self._gateway_request(
                "GET",
                f"/sems-plant/api/equipments/{sn}/telecounting",
                query={"deviceType": "INVERTER", "pwId": powerStationId},
                maxTokenRetries=maxTokenRetries,
                operation_name=f"getData telecounting {sn}",
            )

            telemetry_flat = self._flatten_gateway_factors(telemetry)
            telecounting_flat = self._flatten_gateway_factors(telecounting)

            pac_kw = self._number(telemetry_flat.get("pAc"))
            eday = self._number(telecounting_flat.get("proPvStatsToday"))
            etotal = self._number(telecounting_flat.get("proPvStatsTotal"))
            temperature = telemetry_flat.get("Temperature")

            capacity = device.get("capacity")
            if capacity is None:
                capacity = basic_info.get("pvCapacity")
            if capacity is None:
                capacity = basic_info.get("installedPower")

            legacy_full: dict[str, Any] = {
                "sn": sn,
                "name": device.get("name"),
                "status": device.get("status"),
                "capacity": capacity,
                "pac": pac_kw * 1000 if pac_kw is not None else None,
                "eday": eday,
                "etotal": etotal,

                # GOODWE_SPELLING.temperature uses the historic typo
                # "tempperature", so keep both forms.
                "temperature": temperature,
                "tempperature": temperature,

                "vpv1": telemetry_flat.get("MPPT-1:Vpv"),
                "ipv1": telemetry_flat.get("MPPT-1:Ipv"),
                "vpv2": telemetry_flat.get("MPPT-2:Vpv"),
                "ipv2": telemetry_flat.get("MPPT-2:Ipv"),
                "vpv3": telemetry_flat.get("MPPT-3:Vpv"),
                "ipv3": telemetry_flat.get("MPPT-3:Ipv"),
                "vpv4": telemetry_flat.get("MPPT-4:Vpv"),
                "ipv4": telemetry_flat.get("MPPT-4:Ipv"),

                "vac1": telemetry_flat.get("PHASE-A:Vac"),
                "iac1": telemetry_flat.get("PHASE-A:Iac"),
                "fac1": telemetry_flat.get("Fac"),
                "vac2": telemetry_flat.get("PHASE-B:Vac"),
                "iac2": telemetry_flat.get("PHASE-B:Iac"),
                "fac2": telemetry_flat.get("Fac"),
                "vac3": telemetry_flat.get("PHASE-C:Vac"),
                "iac3": telemetry_flat.get("PHASE-C:Iac"),
                "fac3": telemetry_flat.get("Fac"),
            }

            inverter = {
                "sn": sn,
                "name": device.get("name"),
                "status": device.get("status"),
                "capacity": capacity,
                "pac": legacy_full["pac"],
                "eday": eday,
                "etotal": etotal,
                "temperature": temperature,
                "tempperature": temperature,
                "invert_full": legacy_full,
            }
            inverters.append(inverter)

        pac_values = [
            x.get("pac") for x in inverters
            if isinstance(x.get("pac"), (int, float))
        ]
        day_values = [
            x.get("eday") for x in inverters
            if isinstance(x.get("eday"), (int, float))
        ]
        total_values = [
            x.get("etotal") for x in inverters
            if isinstance(x.get("etotal"), (int, float))
        ]

        result: dict[str, Any] = {
            "info": {
                "stationname": basic_info.get("name"),
                "capacity": (
                    basic_info.get("pvCapacity")
                    if basic_info.get("pvCapacity") is not None
                    else basic_info.get("installedPower")
                ),
                "address": basic_info.get("googleAddress") or basic_info.get("address"),
                "latitude": basic_info.get("latitude"),
                "longitude": basic_info.get("longitude"),
                "status": basic_info.get("status"),
            },
            "kpi": {
                "pac": sum(pac_values) if pac_values else None,
                "power": sum(day_values) if day_values else None,
                "total_power": sum(total_values) if total_values else None,
            },
            "inverter": inverters,
        }

        try:
            flow = self.getFlow(
                powerStationId,
                renewToken=False,
                maxTokenRetries=maxTokenRetries,
            )
            if isinstance(flow, dict) and flow:
                result["powerflow"] = flow
        except (SemsRateLimitedError, OutOfRetries):
            raise
        except Exception as exception:  # noqa: BLE001
            _LOGGER.debug("SEMS - Flow enrichment skipped: %s", exception)

        if not inverters and not basic_info:
            _LOGGER.error(
                "SEMS - Gateway getData returned neither station info nor inverter data"
            )
            return {}

        _LOGGER.debug(
            "SEMS - Gateway getData built legacy payload: station=%s inverters=%s pac=%s",
            result["info"].get("stationname"),
            len(inverters),
            result["kpi"].get("pac"),
        )
        return result

    def getFlow(
        self,
        powerStationId: str,
        renewToken: bool = False,
        maxTokenRetries: int = 2,
    ) -> dict[str, Any]:
        """Get current SEMS Plus power flow data."""

        url_part = f"{_FlowURLPart}?stationId={powerStationId}"

        if maxTokenRetries <= 0:
            _LOGGER.info("SEMS - Maximum token fetch tries reached, aborting flow request")
            raise OutOfRetries

        context = self._get_authenticated_request_context(
            url_part,
            renewToken,
            "getFlow API call",
        )

        if context is None:
            return {}

        api_url, headers = context

        try:
            json_response = self._make_http_request(
                api_url,
                headers,
                operation_name="getFlow API call",
                validate_code=True,
                method="GET",
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
