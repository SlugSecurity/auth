from contracts import NativeRuntime, ProductionRuntime

NATIVE_NAMES = (
    "approved_accounts",
    "members",
    "officers",
    "enrollment_service",
    "enrollment_workers",
    "authorization_reader",
    "privileged_accounts",
    "membership_controller",
    "membership_controllers",
    "posix_provisioner",
    "directory_reader",
    "account_portal",
)


def native_name(name: str, runtime: NativeRuntime) -> str:
    if name not in NATIVE_NAMES:
        raise KeyError(name)

    if isinstance(runtime, ProductionRuntime):
        return name

    resolver = getattr(runtime, "native_name", None)

    if not callable(resolver):
        raise RuntimeError("Local runtime native name resolver is unavailable")

    result: object = resolver(name)

    if not isinstance(result, str) or not result:
        raise RuntimeError(
            "Local runtime native name resolver returned an invalid name"
        )

    return result
