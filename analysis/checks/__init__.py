"""Netwise checks -- one module per feature, one `run(bf)` function each.

A check here is a PRODUCER: it receives a Batfish session with one snapshot
loaded, and returns findings about it.

    access_control.py    Arsh      (written -- use it as the template)
    routing.py           Ankeet    (written)
    policy_compliance.py Shubham   (written)
    risk.py              Samika    (to do -- but NOT as a check, see below)

Register your module in the CHECKS dictionary in analysis/pipeline.py.

TWO FEATURES DO NOT BELONG IN THIS FOLDER
    See docs/design/pipeline-feature-shapes.md. Both were originally planned as
    checks and neither can be one:

    change_impact  compares TWO snapshots (differentialReachability needs a
                   reference), and the registry hands a check exactly one. It
                   becomes a separate entry point, analyse_change(before,
                   after), called directly rather than registered. DO NOT add
                   change_impact.py here or to CHECKS.

    risk           needs the COMBINED findings from every other check, not a
                   Batfish session. Registered as a peer it would be the one
                   check unable to see what it is meant to prioritise. It
                   becomes a post-processor, refine(results) -> results,
                   running after the check loop.

    F-1 is unaffected either way -- both still return findings in the agreed
    format with their agreed id prefixes. Only the INPUT contract differs.
"""
