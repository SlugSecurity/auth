# SlugSec auth

Kanidm setup for slug security

```sh
nix develop
nix fmt
nix run .#check

export KANIDM_URL=https://auth.slugsec.club KANIDM_NAME=your_admin_username
kanidm login
kanidm reauth

kanidm person create guest_example "Example Guest"
kanidm person update guest_example --displayname "Updated Name" --mail slugsec-infra-group@ucsc.edu
kanidm person credential create-reset-token guest_example --ttl 600

kanidm group create example_users idm_admin
kanidm group add-members example_users guest_example
kanidm group list-members example_users
kanidm group remove-members example_users guest_example

kanidm system oauth2 create example "Example app" https://example.slugsec.club
kanidm system oauth2 add-redirect-url example https://example.slugsec.club/callback
kanidm system oauth2 enable-strict-redirect-url example
kanidm system oauth2 update-scope-map example example_users openid profile email
kanidm system oauth2 prefer-short-username example
kanidm system oauth2 show-basic-secret example
```
