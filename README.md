# audisp-auditdistd

A plugin for the Linux audit event dispatcher audispd to push audit trail logs over to a FreeBSD auditdistd daemon.

## Background

This project is a continuation of a Google Summer of Code 2016 project for FreeBSD.
The original and final goal of the project is to allow a FreeBSD user to collect and process audit trails from different systems like Linux and Windows.
At the moment, the goal is to add an audispd plugin capable of communicating with FreeBSD auditdistd.

## Dependencies

```sh
apt install libssl-dev
```

## See also

* Non-BSM to BSM Conversion Tools project for Google Summer of Code 2016 at FreeBSD: https://wiki.freebsd.org/SummerOfCode2016/NonBSMtoBSMConversionTools
