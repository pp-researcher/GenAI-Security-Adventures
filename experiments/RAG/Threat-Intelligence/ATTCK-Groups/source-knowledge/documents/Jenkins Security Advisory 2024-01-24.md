Jenkins Security Advisory 2024-01-24                                        
[Jenkins Security Home](/security/)


Jenkins Security Advisory 2024-01-24
====================================

This advisory announces vulnerabilities in the following Jenkins deliverables:

*   Jenkins (core)
*   [Git server Plugin](https://plugins.jenkins.io/git-server)
*   [GitLab Branch Source Plugin](https://plugins.jenkins.io/gitlab-branch-source)
*   [Log Command Plugin](https://plugins.jenkins.io/log-command)
*   [Matrix Project Plugin](https://plugins.jenkins.io/matrix-project)
*   [Qualys Policy Compliance Scanning Connector Plugin](https://plugins.jenkins.io/qualys-pc)
*   [Red Hat Dependency Analytics Plugin](https://plugins.jenkins.io/redhat-dependency-analytics)

Descriptions
------------

### Arbitrary file read vulnerability through the CLI can lead to RCE

**SECURITY-3314 / CVE-2024-23897**  
**Severity (CVSS):** [Critical](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)  
**Description:**

Jenkins has a built-in [command line interface (CLI)](/doc/book/managing/cli/) to access Jenkins from a script or shell environment.

Jenkins uses the [args4j library](https://github.com/kohsuke/args4j) to parse command arguments and options on the Jenkins controller when processing CLI commands. This command parser has a feature that replaces an `@` character followed by a file path in an argument with the file’s contents (`expandAtFiles`). This feature is enabled by default and Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable it.

This allows attackers to read arbitrary files on the Jenkins controller file system using the default character encoding of the Jenkins controller process.

*   Attackers with Overall/Read permission can read entire files.
    
*   Attackers **without** Overall/Read permission can read the first few lines of files. The number of lines that can be read depends on available CLI commands. As of publication of this advisory, the Jenkins security team has found ways to read the first three lines of files in recent releases of Jenkins without having any plugins installed, and has not identified any plugins that would increase this line count.
    

Binary files containing cryptographic keys used for various Jenkins features can also be read, with some limitations (see [note on binary files below](#binary-files-note)). As of publication, the Jenkins security team has confirmed the following possible attacks in addition to reading contents of all files with a known file path. All of them leverage attackers' ability to obtain cryptographic keys from binary files, and are therefore only applicable to instances where that is feasible.

This list is not definitive. Further attacks likely exist, including ones that do not need attackers to obtain cryptographic keys from binary files.

*   **Remote code execution via Resource Root URLs** (Variant 1)  
    Exploitation requires that all of the following conditions are met:
    
    *   The "Resource Root URL" functionality is enabled (see [documentation](/doc/book/security/user-content/#resource-root-url)).
        
    *   The CLI WebSocket endpoint is accessible. This requires that Jenkins is running on a version of Jetty for which Jenkins supports WebSockets. This is the case when using the provided native installers, packages, or the Docker containers, as well as when running Jenkins with the command `java -jar jenkins.war`. Additionally, reverse proxies may not allow WebSocket requests if improperly configured.
        
    *   Attackers can retrieve binary secrets (see [note below](#binary-files-note)).
        
    *   Attackers know, or can guess, the user name of any user with Overall/Read permission.
        
    
*   **Remote code execution via Resource Root URLs** (Variant 2)  
    Exploitation requires that all of the following conditions are met:
    
    *   The "Resource Root URL" functionality is enabled (see [documentation](/doc/book/security/user-content/#resource-root-url)).
        
    *   Attackers can retrieve binary secrets (see [note below](#binary-files-note)).
        
    *   The attacker needs an API token for a (non-anonymous) user account. It is not necessary for this user account to (still) have Overall/Read permission.
        
    
*   **Remote code execution via "Remember me" cookie**  
    Forging a "Remember me" cookie allows attackers to log in to Jenkins using a web browser, thereby gaining access to the Script Console if they forge a cookie for an administrator account. Exploitation requires that all of the following conditions are met:
    
    *   The "Remember me" feature is enabled (the default).
        
    *   Attackers can retrieve binary secrets (see [note below](#binary-files-note)).
        
    *   Attackers have Overall/Read permission to be able to read content in files beyond the first few lines.
        
    
*   **Remote code execution via stored cross-site scripting (XSS) attacks through build logs**  
    Forging serialized console note objects allows implementing XSS attacks by injecting arbitrary HTML and JavaScript into build logs. This attack bypasses the protections added for [SECURITY-382 in the 2017-02-01 security advisory](/security/advisory/2017-02-01/#persisted-cross-site-scripting-vulnerability-in-console-notes). Exploitation requires that all of the following conditions are met:
    
    *   Attackers can control build log output (e.g., through pull requests).
        
    *   Attackers can retrieve binary secrets (see [note below](#binary-files-note)).
        
    
*   **Remote code execution via CSRF protection bypass**  
    Forged CSRF tokens ("crumbs") can be used to implement CSRF attacks by sending POST requests with a valid crumb. Exploitation requires that all of the following conditions are met:
    
    *   Attackers can retrieve binary secrets (see [note below](#binary-files-note)).
        
    *   The web session ID is not part of CSRF crumbs. By default it is (see [SECURITY-626 in the 2019-07-17 security advisory](/security/advisory/2019-07-17/#SECURITY-626)), but not if one of the following conditions is met:
        
        *   Jenkins uses the default crumb issuer and the [Java system property `hudson.security.csrf.DefaultCrumbIssuer.EXCLUDE_SESSION_ID`](/doc/book/managing/system-properties/#hudson-security-csrf-defaultcrumbissuer-exclude_session_id) is set to `true`.
            
        *   Jenkins uses the [Strict Crumb Issuer Plugin](https://plugins.jenkins.io/strict-crumb-issuer/) to generate crumbs and the option "Check the session ID" is unchecked.
            
        
    
*   **Decrypt secrets stored in Jenkins**  
    Jenkins typically uses secrets to access other systems, like SCMs, external user directories for security realms, cloud providers, deployment targets, etc. Exploitation requires that all of the following conditions are met:
    
    *   Attackers can retrieve binary secrets (see [note below](#binary-files-note)).
        
    *   Attackers have access to encrypted secrets. This may require Overall/Read permission, to be able to read content in files beyond the first few lines, but there are other possible sources, like `JENKINS_HOME` backups even if they exclude `secrets/`, or [Configuration as Code](https://plugins.jenkins.io/configuration-as-code/) YAML files.
        
    
*   **Delete any item in Jenkins**  
    Exploitation requires that all of the following conditions are met:
    
    *   The "Resource Root URL" functionality is enabled (see [documentation](/doc/book/security/user-content/#resource-root-url)).
        
    *   Attackers can retrieve binary secrets (see [note below](#binary-files-note)).
        
    *   Attackers know, or can guess, the user name of any user with Overall/Read permission.
        
    
*   **Download a Java heap dump** of the Jenkins controller process or any agent process  
    Exploitation requires that all of the following conditions are met:
    
    *   The "Resource Root URL" functionality is enabled (see [documentation](/doc/book/security/user-content/#resource-root-url)).
        
    *   Attackers can retrieve binary secrets (see [note below](#binary-files-note)).
        
    *   Attackers know, or can guess, the user name of any user with Overall/Read permission.
        
    *   The Jenkins controller or agent process is running on a Java runtime that allows the creation of heap dump files without `.hprof` file extension. Due to [JENKINS-72579](https://issues.jenkins.io/browse/JENKINS-72579) the affected feature does not work by default on recent releases of OpenJDK/HotSpot based JVMs.
        
    

Impact of reading arbitrary files

We have previously considered arbitrary file read vulnerabilities to only have an impact on confidentiality. As a result of the report provided by Yaniv Nizry (SonarSource) and the additional research done by the Jenkins security team resulting in the list above, future vulnerabilities of this kind will likewise be considered to have a high score across all impact metrics (confidentiality, integrity, and availability).

Limitations for reading binary files

While files containing binary data can be read, the affected feature attempts to read them as strings using the controller process’s default character encoding. This is likely to result in some bytes not being read successfully and being replaced with a placeholder value. Which bytes can or cannot be read depends on this character encoding. For example, attempting to read random binary data using UTF-8, roughly half of all bytes will be replaced with a placeholder for an illegal value. For 32 byte random binary secrets, as commonly used in Jenkins for [HMAC-SHA256](https://en.wikipedia.org/wiki/HMAC), this would require attackers to correctly guess on average 16 bytes, which is infeasible. In contrast, with the encoding Windows-1252, only 5 out of 256 possible values are illegal and would be replaced with a placeholder. This is a significantly lower number of bytes to guess in a binary secret on average, as well as fewer possible options for each byte.

Telemetry submissions received from Jenkins 2.437 and later indicate that more than 90% of Jenkins instances reporting anonymous usage statistics use UTF-8 as default character encoding. Almost all instances running on Linux and Mac OS X use UTF-8. Instances on Windows are more likely than not to use a character set that makes it feasible to implement exploits involving reading binary files (like Windows-1252).

To determine whether you’re likely affected by the most severe impacts described above, check the value of the `file.encoding` system property in _Manage Jenkins » System Information_.

While it is _unlikely_ that randomly generated keys use significantly fewer than average of the byte values that cannot be read using a character encoding like UTF-8, it isn’t _impossible_. Therefore administrators should update Jenkins in a timely manner, regardless of the value of `file.encoding`.

**Fix Description:**  
Jenkins 2.442, LTS 2.426.3 disables the command parser feature that replaces an `@` character followed by a file path in an argument with the file’s contents for CLI commands.

In case of problems with this fix, disable this change by setting the [Java system property `hudson.cli.CLICommand.allowAtSyntax`](/doc/book/managing/system-properties/#hudson-cli-clicommand-allowatsyntax) to `true`. Doing this is strongly discouraged on any network accessible by users who are not Jenkins administrators.

**Workaround:**  
Disabling access to the CLI is expected to prevent exploitation completely. Doing so is strongly recommended to administrators unable to immediately update to Jenkins 2.442, LTS 2.426.3. Applying this workaround does not require a Jenkins restart. For instructions, see the [documentation for this workaround](https://github.com/jenkinsci-cert/SECURITY-3314-3315/).

Disabling the CLI is only intended as a short-term workaround, even if you do not use the CLI.

### Cross-site WebSocket hijacking vulnerability in the CLI

**SECURITY-3315 / CVE-2024-23898**  
**Severity (CVSS):** [High](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)  
**Description:**

Jenkins has a built-in [command line interface (CLI)](/doc/book/managing/cli/) to access Jenkins from a script or shell environment. Since Jenkins 2.217 and LTS 2.222.1, one of the ways to communicate with the CLI is through a WebSocket endpoint. This endpoint relies on the default Jenkins web request authentication functionality, like HTTP Basic authentication with API tokens, or session cookies. This endpoint is enabled when running on a version of Jetty for which Jenkins supports WebSockets. This is the case when using the provided native installers, packages, or the Docker containers, as well as when running Jenkins with the command `java -jar jenkins.war`.

Jenkins 2.217 through 2.441 (both inclusive), LTS 2.222.1 through 2.426.2 (both inclusive) does not perform origin validation of requests made through the CLI WebSocket endpoint, resulting in a cross-site WebSocket hijacking (CSWSH) vulnerability.

Additionally, Jenkins does not set an explicit `SameSite` attribute for session cookies. This can allow cross-site requests to make use of the session cookie, i.e., those requests are sent with the logged-in user’s authentication.

In recent releases of Google Chrome and Microsoft Edge the default behavior is for the `SameSite` cookie attribute to be considered `Lax` if not explicitly set. This results in no session cookie being sent with a cross-site request to the WebSocket endpoint, resulting in CLI use as the anonymous user. Mozilla Firefox has an option for this behavior, but it is disabled by default as of publication of this advisory. See [this browser compatibility table](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#browser_compatibility) (row labeled _Defaults to_ `_Lax_`) for details.

This vulnerability allows attackers to execute CLI commands on the Jenkins controller. The impact depends on the permissions of the anonymous user and/or the browser(s) used by the victim(s) of the CSWSH attack:

*   **The anonymous user has no permissions and Jenkins users use web browsers with `SameSite` cookie attribute `Lax` as default**  
    Attackers can execute the `who-am-i` CLI command, obtaining limited information about the anonymous user in Jenkins. This mostly allows exploiting [SECURITY-3314](#SECURITY-3314) and reading the first few lines of files on the Jenkins controller. See that issue for more information about the potential impact.
    
*   **The anonymous user has permissions**  
    This is the case with an authorization strategy like "Anyone can do anything", or when the anonymous user has explicitly been granted additional permissions. Attackers can execute the CLI commands that these permissions allow using, up to and including Groovy scripting capabilities (`groovy` and `groovysh` commands) resulting in arbitrary code execution. If the anonymous user has (only) Overall/Read permission, attackers can obtain the full contents of files by exploiting [SECURITY-3314](#SECURITY-3314) as described in that issue.
    
*   **Jenkins users use web browsers with `SameSite` cookie attribute `Lax` not being the default**  
    The session and/or "Remember me" cookie will be sent with the cross-site request, and the user will be authenticated. Attackers can execute the CLI commands that the victim’s permissions allow using, up to and including Groovy scripting capabilities (`groovy` and `groovysh` commands) in case of a Jenkins administrator, resulting in arbitrary code execution.
    

**Fix Description:**  
Jenkins 2.442, LTS 2.426.3 performs origin validation of requests made through the CLI WebSocket endpoint.

In case of problems with this fix, disable this change by setting the [Java system property `hudson.cli.CLIAction.ALLOW_WEBSOCKET`](/doc/book/managing/system-properties/#hudson-cli-cliaction-allow_websocket) to `true`.

**Workaround:**  
Some workarounds are available to mitigate some or all of the impact if you are unable to immediately upgrade to Jenkins 2.442, LTS 2.426.3:

*   **Disable CLI access**  
    Disabling access to the CLI will prevent exploitation completely and is the **recommended workaround** for administrators unable to immediately update. Applying this workaround does not require a Jenkins restart. For instructions, see the [documentation for this workaround](https://github.com/jenkinsci-cert/SECURITY-3314-3315/).
    
*   **Prevent WebSocket access using a reverse proxy**  
    If Jenkins is accessible only through a reverse proxy, configure that proxy to prevent access to the CLI via WebSocket by not upgrading requests.
    

Administrators of Jenkins instances accessed through a reverse proxy can follow the instructions below to test whether WebSocket endpoints can be reached. These instructions assume that the reverse proxy is not set up to support only selected WebSocket endpoints (e.g., only the CLI).

1.  Log in to Jenkins as a user with Overall/Administer permission.
    
2.  Open your web browser’s developer tools while viewing the Jenkins dashboard.
    
3.  On the _Console_ tab, paste the following script:
    

    new WebSocket(document.location.toString().replace('http', 'ws') + 'wsecho/')

On the _Network_ tab, if the `wsecho/` request resulted in a `101 Switching Protocols` response, WebSocket endpoints can be accessed. A `400 Bad Request` response, or lack of response (in Google Chrome), indicates that WebSocket endpoints cannot be accessed. A `403 Forbidden` response indicates that the necessary Overall/Administer permission is missing.

These steps have been validated in Google Chrome, Mozilla Firefox, and Apple Safari.

### Arbitrary file read vulnerability in Git server Plugin can lead to RCE

**SECURITY-3319 / CVE-2024-23899**  
**Severity (CVSS):** [High](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)  
**Affected plugin: [`git-server`](https://plugins.jenkins.io/git-server)**  
**Description:**

Git server Plugin uses the [args4j library](https://github.com/kohsuke/args4j) to parse command arguments and options on the Jenkins controller when processing Git commands received via SSH. This command parser has a feature that replaces an `@` character followed by a file path in an argument with the file’s contents (`expandAtFiles`). This feature is enabled by default and Git server Plugin 99.va\_0826a\_b\_cdfa\_d and earlier does not disable it.

This allows attackers with Overall/Read permission to read the first two lines of arbitrary files on the Jenkins controller file system using the default character encoding of the Jenkins controller process.

See [SECURITY-3314](#SECURITY-3314) for further information about the potential impact of being able to read files on the Jenkins controller, as well as the [limitations for reading binary files](#binary-files-note). Note that for this issue, unlike SECURITY-3314, attackers need Overall/Read permission.

**Fix Description:**  
Git server Plugin 99.101.v720e86326c09 disables the command parser feature that replaces an `@` character followed by a file path in an argument with the file’s contents for CLI commands.

**Workaround:**  
Navigate to _Manage Jenkins » Security_ and ensure that the _SSHD Port_ setting in the _SSH Server_ section is set to _Disable_. This disables access to Git repositories hosted by Jenkins (and the Jenkins CLI) via SSH.

### Path traversal vulnerability in Matrix Project Plugin

**SECURITY-3289 / CVE-2024-23900**  
**Severity (CVSS):** [Medium](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:L)  
**Affected plugin: [`matrix-project`](https://plugins.jenkins.io/matrix-project)**  
**Description:**

Matrix Project Plugin 822.v01b\_8c85d16d2 and earlier does not sanitize user-defined axis names of multi-configuration projects submitted through the `config.xml` REST API endpoint.

This allows attackers with Item/Configure permission to create or replace any `config.xml` file on the Jenkins controller file system with content not controllable by the attackers.

Matrix Project Plugin 822.824.v14451b\_c0fd42 sanitizes user-defined axis names of Multi-configuration project.

### Shared projects are unconditionally discovered by GitLab Branch Source Plugin

**SECURITY-3040 / CVE-2024-23901**  
**Severity (CVSS):** [Medium](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N)  
**Affected plugin: [`gitlab-branch-source`](https://plugins.jenkins.io/gitlab-branch-source)**  
**Description:**

GitLab allows sharing a project with another group.

GitLab Branch Source Plugin 684.vea\_fa\_7c1e2fe3 and earlier unconditionally discovers projects that are shared with the configured owner group.

This allows attackers to configure and share a project, resulting in a crafted Pipeline being built by Jenkins after the next scan of the group’s projects.

In GitLab Branch Source Plugin 688.v5fa\_356ee8520, the default strategy for discovering projects does not discover projects shared with the configured owner group. To discover projects shared with the configured owner group, use the new trait "Discover shared projects".

After updating, any shared project that has already been discovered will be removed unless the new trait is added to the organization folder configuration before running a scan.

### CSRF vulnerability in GitLab Branch Source Plugin

**SECURITY-3251 / CVE-2024-23902**  
**Severity (CVSS):** [Medium](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N)  
**Affected plugin: [`gitlab-branch-source`](https://plugins.jenkins.io/gitlab-branch-source)**  
**Description:**

GitLab Branch Source Plugin 684.vea\_fa\_7c1e2fe3 and earlier does not require POST requests for a form validation endpoint, resulting in a cross-site request forgery (CSRF) vulnerability.

This vulnerability allows attackers to connect to an attacker-specified URL.

GitLab Branch Source Plugin 688.v5fa\_356ee8520 requires POST requests for the affected form validation endpoint.

### Non-constant time webhook token comparison in GitLab Branch Source Plugin

**SECURITY-2871 / CVE-2024-23903**  
**Severity (CVSS):** [Low](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)  
**Affected plugin: [`gitlab-branch-source`](https://plugins.jenkins.io/gitlab-branch-source)**  
**Description:**

GitLab Branch Source Plugin 684.vea\_fa\_7c1e2fe3 and earlier does not use a constant-time comparison function when checking whether the provided and expected webhook token are equal.

This could potentially allow attackers to use statistical methods to obtain a valid webhook token.

GitLab Branch Source Plugin 688.v5fa\_356ee8520 uses a constant-time comparison function when validating the webhook token.

### Stored XSS vulnerability in Qualys Policy Compliance Scanning Connector Plugin

**SECURITY-3006 / CVE-2023-6148**  
**Severity (CVSS):** [High](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H)  
**Affected plugin: [`qualys-pc`](https://plugins.jenkins.io/qualys-pc)**  
**Description:**

Qualys Policy Compliance Scanning Connector Plugin 1.0.5 and earlier does not escape Qualys API responses displayed on the job configuration page.

This results in a stored cross-site scripting (XSS) vulnerability exploitable by attackers able to configure jobs.

Qualys Policy Compliance Scanning Connector Plugin 1.0.6 escapes Qualys API responses displayed on the job configuration page.

### XXE vulnerability in Qualys Policy Compliance Scanning Connector Plugin

**SECURITY-3005 / CVE-2023-6147**  
**Severity (CVSS):** [High](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N)  
**Affected plugin: [`qualys-pc`](https://plugins.jenkins.io/qualys-pc)**  
**Description:**

Qualys Policy Compliance Scanning Connector Plugin 1.0.5 and earlier does not configure its XML parser to prevent XML external entity (XXE) attacks.

This allows attackers able to configure jobs to have Jenkins parse a crafted HTTP response with XML data that uses external entities for extraction of secrets from the Jenkins controller or server-side request forgery.

Qualys Policy Compliance Scanning Connector Plugin 1.0.6 disables external entity resolution for its XML parser.

### Incorrect permission checks in Qualys Policy Compliance Scanning Connector Plugin allow capturing credentials

**SECURITY-3007 / CVE pending**  
**Severity (CVSS):** [Medium](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N)  
**Affected plugin: [`qualys-pc`](https://plugins.jenkins.io/qualys-pc)**  
**Description:**

Qualys Policy Compliance Scanning Connector Plugin 1.0.5 and earlier does not correctly perform permission checks in several HTTP endpoints.

This allows attackers with global Item/Configure permission (while lacking Item/Configure permission on any particular job) to connect to an attacker-specified URL using attacker-specified credentials IDs obtained through another method, capturing credentials stored in Jenkins.

Qualys Policy Compliance Scanning Connector Plugin 1.0.6 requires the appropriate permissions for the affected HTTP endpoints.

### Content-Security-Policy protection for user content disabled by Red Hat Dependency Analytics Plugin

**SECURITY-3322 / CVE-2024-23905**  
**Severity (CVSS):** [High](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H)  
**Affected plugin: [`redhat-dependency-analytics`](https://plugins.jenkins.io/redhat-dependency-analytics)**  
**Description:**

Jenkins sets the `Content-Security-Policy` header to static files served by Jenkins (specifically `DirectoryBrowserSupport`), such as workspaces, `/userContent`, or archived artifacts, unless a Resource Root URL is specified.

Red Hat Dependency Analytics Plugin 0.7.1 and earlier globally disables the `Content-Security-Policy` header for static files served by Jenkins whenever the 'Invoke Red Hat Dependency Analytics (RHDA)' build step is executed. This allows cross-site scripting (XSS) attacks by users with the ability to control files in workspaces, archived artifacts, etc.

Jenkins instances with [Resource Root URL](/doc/book/security/user-content/#resource-root-url) configured are unaffected.

Red Hat Dependency Analytics Plugin 0.9.0 does not disable the `Content-Security-Policy` header for static files served by Jenkins anymore.

### Arbitrary file read vulnerability in Log Command Plugin

**SECURITY-3334 / CVE-2024-23904**  
**Severity (CVSS):** [High](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)  
**Affected plugin: [`log-command`](https://plugins.jenkins.io/log-command)**  
**Description:**

Log Command Plugin uses the [args4j library](https://github.com/kohsuke/args4j) to parse command arguments and options on the Jenkins controller when processing commands received via instant messaging platforms such as IRC or Jabber. This command parser has a feature that replaces an `@` character followed by a file path in an argument with the file’s contents (`expandAtFiles`). This feature is enabled by default and Log Command Plugin 1.0.2 and earlier does not disable it.

This allows unauthenticated attackers to read the first line of arbitrary files on the Jenkins controller file system using the default character encoding of the Jenkins controller process.

See [SECURITY-3314](#SECURITY-3314) for further information about the potential impact of being able to read files on the Jenkins controller, as well as the [limitations for reading binary files](#binary-files-note).

The severity of this issue assumes attackers have no access to Jenkins other than via instant messaging platforms. If attackers can access Jenkins (even lacking Overall/Read permission), the severity is [critical](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

As of publication of this advisory, there is no fix. [Learn why we announce this.](/security/plugins/#unresolved)

Severity
--------

*   SECURITY-2871: [Low](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)
*   SECURITY-3005: [High](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N)
*   SECURITY-3006: [High](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H)
*   SECURITY-3007: [Medium](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N)
*   SECURITY-3040: [Medium](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N)
*   SECURITY-3251: [Medium](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N)
*   SECURITY-3289: [Medium](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:L)
*   SECURITY-3314: [Critical](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
*   SECURITY-3315: [High](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
*   SECURITY-3319: [High](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)
*   SECURITY-3322: [High](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H)
*   SECURITY-3334: [High](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

Affected Versions
-----------------

*   **Jenkins weekly** up to and including 2.441
*   **Jenkins LTS** up to and including 2.426.2
*   **Git server Plugin** up to and including 99.va\_0826a\_b\_cdfa\_d
*   **GitLab Branch Source Plugin** up to and including 684.vea\_fa\_7c1e2fe3
*   **Log Command Plugin** up to and including 1.0.2
*   **Matrix Project Plugin** up to and including 822.v01b\_8c85d16d2
*   **Qualys Policy Compliance Scanning Connector Plugin** up to and including 1.0.5
*   **Red Hat Dependency Analytics Plugin** up to and including 0.7.1

Fix
---

*   **Jenkins weekly** should be updated to version 2.442
*   **Jenkins LTS** should be updated to version 2.426.3
*   **Git server Plugin** should be updated to version 99.101.v720e86326c09
*   **GitLab Branch Source Plugin** should be updated to version 688.v5fa\_356ee8520
*   **Matrix Project Plugin** should be updated to version 822.824.v14451b\_c0fd42
*   **Qualys Policy Compliance Scanning Connector Plugin** should be updated to version 1.0.6
*   **Red Hat Dependency Analytics Plugin** should be updated to version 0.9.0

These versions include fixes to the vulnerabilities described above. All prior versions are considered to be affected by these vulnerabilities unless otherwise indicated.

As of publication of this advisory, no fixes are available for the following plugins:



