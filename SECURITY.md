# Security

What Leaves Home reads DNS logs and runs an agent as root on home servers, so security reports matter.

## Reporting a problem

Please report it privately: on this repository's **Security** tab, choose **Report a vulnerability**. Don't open a public issue.

Include what you found, how to reproduce it, and the version (shown in the page footer and in `docker logs whatleaves`). You'll get a reply within a week. Fixes go out as a new release, and the report is credited unless you'd rather not be named.

## Supported versions

Only the latest release gets fixes while the project is at 0.x.

## What's in scope

- The app: login, setup code, sessions, the Host and Origin checks, the ingest API
- The agent and its installer, including the checksum check
- The container images and the release workflow

Out of scope: problems that need someone already in control of your server, or a What Leaves Home page deliberately exposed to the internet against the README's advice.
