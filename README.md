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

### Development environment

Install the global dependency (bpf is not installable through pip):

```shell
sudo apt install python3-bpfcc
```

Create a virtual environment that can use global packages and install the pip dependencies:

```shell
python3 -m venv venv-name --system-site-packages
source venv-name/bin/activate
pip install -r requirements.txt
```

The daemon needs root permissions, and using sudo resets environment variables, including the virtual environment python path. To launch the daemon from the virtual environment, check the venv python path and use it when starting the daemon:

```shell
which python3
sudo path/to/venv/python3 -m proton.vpn.daemon
```

To use the app in the same virtual environment, install it through pip and launch it from a different terminal.