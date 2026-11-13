"""Method 2 setup: register cor.'s onboarding app, once, in cor.'s own tenant.

The onboarding app is a multi-tenant PUBLIC client (sign-in with PKCE, no
secret) and has no permissions of its own. At sign-in it asks the customer's
admin for delegated Graph scopes, so it can act AS THE ADMIN, only during that
sign-in, to create the SPN in the customer's tenant (what the PS script does).

  python method2_setup.py register
  python method2_setup.py show
  python method2_setup.py remove
"""

import argparse
import sys

from corpoc import auth, graphops, store

APP_NAME = "cor. onboarding (PoC)"
REDIRECT = "http://localhost:8401/m2/callback"
# The Event Hub onboarding (eventhub_portal.py) reuses this app with its own redirect URI.
EVENTHUB_REDIRECT = "http://localhost:8402/eh/callback"
SCOPES = ["https://graph.microsoft.com/Application.ReadWrite.All"]


def sign_in(args):
    login = auth.device_code_login if args.device_code else auth.interactive_login
    token = login(SCOPES, tenant=args.tenant or "organizations")
    c = auth.claims(token)
    print(f"Signed in as {c.get('upn') or c.get('preferred_username')} (tenant {c.get('tid')})\n")
    return token, c.get("tid")


def cmd_register(args):
    token, home = sign_in(args)
    app = graphops.find_app(token, APP_NAME)
    body = {"signInAudience": "AzureADMultipleOrgs",
            "isFallbackPublicClient": True,
            "publicClient": {"redirectUris": [REDIRECT, EVENTHUB_REDIRECT]}}
    if app:
        auth.graph("PATCH", f"/applications/{app['id']}", token, body)
        print(f"Updated '{APP_NAME}' (client ID {app['appId']}).")
    else:
        app = auth.graph("POST", "/applications", token, {
            "displayName": APP_NAME,
            "notes": "cor. onboarding PoC (method 2): signs the customer's admin in to create cor.'s SPN. Safe to delete.",
            **body})
        print(f"Created '{APP_NAME}' (client ID {app['appId']}): multi-tenant, public client, no secret, no permissions.")
    try:
        if graphops.set_logo(token, app["id"]):
            print("Uploaded the cor. logo: Microsoft shows it on the admin's sign-in and consent screens.")
    except auth.HttpError as exc:
        print(f"Could not upload the logo ({exc}); the app works without it.")
    store.save("method2", "onboarding-app", {"appId": app["appId"], "objectId": app["id"],
                                             "homeTenant": home, "redirectUri": REDIRECT,
                                             "eventhubRedirectUri": EVENTHUB_REDIRECT})
    print("\nNext: python method2_portal.py, then open http://localhost:8401/")


def cmd_show(_args):
    record = store.load("method2", "onboarding-app")
    print(record or "Not registered yet: python method2_setup.py register")


def cmd_remove(args):
    record = store.load("method2", "onboarding-app")
    if not record:
        sys.exit("Not registered.")
    token, _ = sign_in(args)
    try:
        auth.graph("DELETE", f"/applications/{record['objectId']}", token)
        print(f"Deleted '{APP_NAME}'. SPNs it created in customer tenants are not affected: the customers own them.")
    except auth.HttpError as exc:
        if exc.status != 404:
            raise
    store.delete("method2", "onboarding-app")


def main():
    # The sign-in options go after the command: `register --tenant <domain>`.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--tenant", help="cor.'s tenant ID or domain (default: the account you pick)")
    common.add_argument("--device-code", action="store_true", help="sign in with a device code instead of the browser")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("register", "show", "remove"):
        sub.add_parser(name, parents=[common])
    args = parser.parse_args()
    try:
        {"register": cmd_register, "show": cmd_show, "remove": cmd_remove}[args.cmd](args)
    except auth.HttpError as exc:
        sys.exit(f"Error: {exc}")


if __name__ == "__main__":
    main()
