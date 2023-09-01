# Hack Directory

This directory contains utility scripts that help manage the codebase, check
consistency, autogenerate code, etc. This document documents what each of them do.

---

`hack/verify-fakes.sh`

This script runs as a presubmit and fails if the fake implementations used for
testing need to be updated. If you find your PR is failing because the fakes are 
out of date, simply run:

```
make fakes
```

This will regenerate all the mocked implementations, then commit the results.
Also, consider checking the unit tests. If fakes are out of date, then probably
tests need to be adjusted.



