What is Mumble?
================

Mumble is a fork of Grumble, and Grumble is an implementation of a server for the Mumble voice chat system. It is an alternative to Murmur, the typical Mumble server.

Mumble takes a different design pattern, drops windows support and will be including a custom feature set implemented as plugins. The design will focus on library support and provide both client and server functionality.

Project status
==============

Grumble is pretty much feature complete, except for a few "minor" things. Mumble forked from Grumble after it already got feature complete, so mumble is essentially feature complete but is already receiving custom features that are not standard to the Mumble protocol, which is why a client is included in mumble to support abstracted/overlayed features that are being applied ontop of Mumble. 

Mumble client/server combo will be security focused and provide terminal and web based client for prototyping and testing. And focus will be put on API support to allow controlling Mumble server from any language. 

There is no bandwidth limiting, and there is no API to remote control it.

Grumble's persistence layer is very ad-hoc. It uses an append-only file to store delta updates to each server's internal data, and periodically, it syncs a server's full data to disk.

Grumble is currently architected to have all data in memory. That means it's not ideal for use with very very large servers. (And large servers in this context are servers with many registered users, ACLs, etc.).

It is architected this way because it allowed me to write a pure-Go program with very few external dependencies, back 4-5 years ago.

The current thinking is that if registered users are taking up too much of your memory, you should use an external authenticator. But that code isn't written yet. The concept would be equivalent to Murmur's authenticator API via RPC. But a Grumble authenticator would probably be set up more akin to a webhook -- so just a URL in the config file.

Then there's the API problem. You can't currently remote control Grumble. Which can make it hard to use in production. I imagine Grumble will grow an API that it makes available via HTTP. Murmur's API is already quite stateless in many regards, so it shouldn't be too much of a stretch to put a RESTful API in Grumble to do the same job.
