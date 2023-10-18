# Development

### Development Container

1. Docker / Podman
2. VSCode (or other supported IDE)
3. Remote-Containers [extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)

### Native

1. Go 1.20+
2. Make

## Getting Started

First, clone this repository and make sure you have your enviornment all setup. </br>
For support IDEs users, you can simply run this project in a container (aka devcontainer): </br>

The option would be available once you install the recommended extension. </br>

See more details [here](https://containers.dev/supporting)

## Code Signoff

Before making a commit, please make sure your git configuration includes your full name and email address. You can do this by running the following commands:

```
git config --global user.name "Your Name"
git config --global user.email "youremail@example.com"
```

When committing code, please include a signoff line in your commit message. You can use the `--signoff` or `-s` flag when using the `git commit` command to automatically add the signoff line. For example:

```
git commit -s -m "Commit message"
```