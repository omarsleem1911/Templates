# Templates

Public ARM templates used by the cor. onboarding POC. They contain resource definitions only: no secrets, keys or customer data.

## eventhub/azuredeploy.json

The cor. Event Hub integration: an Event Hubs namespace, event hub, `corehSAS` shared access policy, and a storage account with the `corcontainer` checkpoint container. Every resource is tagged with the onboarding's connection ID, so cor. can find it after deployment. No connection strings are in the outputs.

The cor. onboarding portal links here so Azure Resource Manager can download the template at deployment time (it refuses `localhost` links). The portal form (`createUiDefinition.json`) is served by the portal itself, because it carries the connection ID.

Source of truth: `spn-onboarding/eventhub/azuredeploy.json` in the onboarding POC. Re-publish this copy whenever that file changes.
