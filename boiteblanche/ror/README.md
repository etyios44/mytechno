# ROR

- Ruby on Rails Security Risk Areas
  - HTTP Header Parsing & Redirection
    - CVE-2023-28362
      - Description: Redirect header injection via `redirect_to` allowing XSS
      - Versions: All Rails < 7.0.5.1, 6.1.7.4
      - Code Example:
        ```
        redirect_to params[:url]
        ```
      - Fix: Validate URLs with `allow_other_host: false`
    - CVE-2023-22795
      - Description: ReDoS in `If-None-Match` header parsing
      - Versions: All Rails < 6.1.7.1 (Ruby < 3.2)
      - Fix: Upgrade Rails + Ruby ≥ 3.2
  - ReDoS in Regular Expressions
    - CVE-2024-41128
      - Description: ReDoS in query parameter filtering (Action Dispatch)
      - Versions: All Rails < 6.1.7.9, 7.0.8.5
      - Code Example:
        ```
        params.permit(:filter).to_h
        ```
      - Fix: Update to Rails ≥ 6.1.7.9
    - CVE-2024-47887
      - Description: ReDoS in HTTP Token authentication
      - Versions: All Rails < 7.1.4.1
      - Fix: Upgrade to Rails ≥ 7.1.4.1
  - Insecure File Handling
    - CVE-2025-XXXXX (Bootsnap Exploit)
      - Description: Arbitrary file write leading to RCE
      - Versions: Apps using Bootsnap with unsafe file paths
      - Code Example:
        ```
        File.join("tmp", params[:filename])
        ```
      - Fix: Sanitize filenames with `File.basename`
  - Image Processing Vulnerabilities
    - CVE-2022-21831
      - Description: Code injection via ActiveStorage image variants
      - Versions: ActiveStorage < 6.1.3.1
      - Code Example:
        ```
        image.variant(resize: params[:size])
        ```
      - Fix: Use validated parameters
  - Rack Framework Vulnerabilities
    - CVE-2025-27610
      - Description: HTTP header parsing DoS
      - Versions: Rack < 3.0.8
      - Fix: Update Rack to ≥ 3.0.8
