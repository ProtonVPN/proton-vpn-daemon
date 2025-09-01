# Proton VPN Core API

The `proton-vpn-daemon` contains all daemons that are required for the linux client. 

## Development

Even though our CI pipelines always test and build releases using Linux
distribution packages, you can use pip to set up your development environment.

To run this in a development environment:

* Make a venv
* Install the gtk app in the venv.
* Install the daemon in the venv.
* Run the daemon as root in the venv.
* Run the gtk app as a normal user in the venv.
* The app should now detect the split tunneling service and run with ST enabled.


### Proton package registry

If you didn't do it yet, to be able to pip install Proton VPN components you'll
need to set up our internal Python package registry. You can do so running the
command below, after replacing `{GITLAB_TOKEN`} with your
[personal access token](https://gitlab.protontech.ch/help/user/profile/personal_access_tokens.md)
with the scope set to `api`.

```shell
pip config set global.index-url https://__token__:{GITLAB_TOKEN}@gitlab.protontech.ch/api/v4/groups/777/-/packages/pypi/simple
```

In the index URL above, `777` is the id of the current root GitLab group,
the one containing the repositories of all our Proton VPN components.

### Virtual environment

You can create the virtual environment and install the rest of dependencies as
follows:

```shell
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
