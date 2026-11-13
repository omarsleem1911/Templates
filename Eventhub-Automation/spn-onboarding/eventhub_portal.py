"""cor. Azure onboarding Hub (http://localhost:8401): separate from the Microsoft 365 flow.

  /     Onboard Azure: the discovery-driven wizard (corpoc/azure_onboard.py, UI in
        corpoc/onboard_ui.html). Sign in, scan, select resources, review the per-region
        Event Hub plan and architecture, deploy, results.
  /eh   The earlier single Event Hub flow (deploy from the Azure portal), kept for reference.

Both use the "cor. onboarding (PoC)" app and its one redirect URI; the callback hands each
sign-in back to the flow that started it.
"""

from corpoc import azure_onboard, eventhub
from corpoc.web import serve

GET_ROUTES = {**eventhub.GET_ROUTES, **azure_onboard.GET_ROUTES}
POST_ROUTES = {**eventhub.POST_ROUTES, **azure_onboard.POST_ROUTES}

if __name__ == "__main__":
    serve(eventhub.PORT, GET_ROUTES, POST_ROUTES, product="Azure onboarding (PoC)")
