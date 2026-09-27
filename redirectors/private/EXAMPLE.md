# Private Redirector Configs

Place operator-specific redirector YAML files in this directory.
They are .gitignore'd and won't be committed to the public repo.

Example file: `my-cdn-redir.yaml`

    name: my-cdn-redir
    type: https
    listen: 0.0.0.0:443
    backend: 10.0.0.5:8443
    domain: cdn-assets.example.com
    trusted: true
    profile: cdn-cloudfront
    allow_user_agents:
      - "Mozilla/5.0*"
    decoy: redirect
    decoy_target: https://www.example.com

Then generate agents:

    sockpuppets> generate 10.0.0.5 8443 --redirector=my-cdn-redir

And deploy configs:

    sockpuppets> redirector-deploy my-cdn-redir nginx
