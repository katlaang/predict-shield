# Real-world web-log request-only applicability pilot

This study uses the committed DVWA v3 frozen model but executes ONLY its request-novelty component and original threshold. The four-component DVWA v3 fusion also requires per-request process, network, file and complete HTTP response evidence, none of which is present in ordinary access logs. It cannot be silently substituted.

Source A: Indonesian public-sector web server logs from https://zenodo.org/records/20001206, MIT publisher license. Organization X archive MD5 b4bf79effa6f3ee1b9e53f278d916620, 2.1 MB. Organization Y is much larger and excluded from default CI. The publisher's pattern-matching labels cannot be used as independent benign truth. Unknown events stay UNKNOWN.

Source B: Polish shop access logs from https://zenodo.org/records/18895701, CC BY 4.0. December 2025, 178,939 requests reported; published MD5 725822e13e09281b498e7cd5d082a039, 28.6 MB. Query values were removed. This supports path-level alert-burden diagnostics, NOT payload-sensitive attack detection.

Other sources assessed, deliberately not downloaded: EClog DOI 10.7910/DVN/Z834IK, rights and files not independently retrievable through Harvard Dataverse; CDSL https://github.com/cdsl-research/website-access-logs-public, GitHub license is null despite some query strings remaining in a sampled log; Biblio-US17 DOI 10.12795/11441/148254, actual files require request access and dataset rights are unverified. Do not infer data rights from article licenses.

Method before seeing results: verify each source file against published MD5, inspect parse coverage, check the frozen DVWA v3 model and code hashes, then score only request_novelty with its unchanged frozen threshold. Count alerts / requests, counts per observed day, source fields missing, and the proportion of paths absent from frozen profiles. No raw paths, IPs, URI parameters or request bodies are committed or uploaded.

Real-web-log labels are unknown. False-positive rate, attack recall, incident frequency and full DVWA v3 operational performance MUST remain null. This is a study of out-of-distribution applicability and request-only alert burden, not validated security outcomes.

Manual independent review remains required to identify actual false alerts. Preselect up to 100 alerted and 100 nonalerted records for privacy-preserving review at an authorized research workstation, recording confirmed malicious / confirmed benign / indeterminate with uncertainty and sampling weights. No human review or independent verification of benign ground truth is claimed. A fresh model adapted to an external site would be a separate, pre-registered experiment rather than a rerun of the same frozen detector.
