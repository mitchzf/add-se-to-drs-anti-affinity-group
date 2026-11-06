# Avi SE anti-affinity ControlScript

`avi-controlscript-se-antiaffinitygroup.py` is an Avi Load Balancer ControlScript. It keeps
Service Engine VMs from the same SE group on separate ESXi hosts. It does this by adding each
new SE VM to a vSphere DRS VM-VM anti-affinity rule. Typically this is done to minimize the
frequency with which vSphere DRS will vMotion SE VMs, which can cause loss of bytes in flight.

## How it works

1. The Avi controller creates a Service Engine, which raises a `CREATED_SE` event.
2. An **alert config** on the controller that watches for `CREATED_SE` raises an alert and
   runs an **alert action**.
3. The alert action on the controller runs this **ControlScript** and passes it the alert as
   JSON, via stdin.
4. The script reads the SE VM name, SE group and cloud name from the alert.
5. The script downloads the encrypted vCenter credentials file (an Avi fileobject) and decrypts
   it with the private key of an Avi certificate.
6. It connects to vCenter and finds the SE VM and its cluster.
7. It asks the Avi API for the Service Engines in the SE group. If the group has fewer than
   two SEs (counting the new one), there's nothing to keep apart, and the script stops without
   changing anything in vCenter. The SE group is the one named by the alert's `obj_uuid`, or,
   without it, the group with that name in the alert's cloud. Every cloud has its own
   `Default-Group`, so the name alone isn't enough.
8. If there are two or more SEs, the script puts the VMs of all of the group's SEs in the
   cluster, including the new one, in the DRS rule
   `avi_se_antiaffinity_<controller FQDN>_<Avi cloud name>_<SE group name>`, creating the rule
   if it doesn't exist. For example:
   `avi_se_antiaffinity_avi.example.com_Default-Cloud_Default-Group`.

The controller FQDN in the rule name is the name of the Avi controller cluster, which the script
reads from the Avi API (`/api/cluster`). It's the same whichever controller node runs the
script. The cloud name comes from the alert.

The script matches the cluster's VMs by name against the Avi API's list of the group's SEs. It
checks which of them the rule already holds and adds only the ones that are missing, so an SE
missed earlier (for example, because an alert was throttled) is added by the next alert for
that group. VMs already in the rule are never removed. SEs of the group in other clusters
aren't added, because a DRS rule can only hold VMs from its own cluster.

vSphere needs at least two VMs in an anti-affinity rule. The rule is therefore created when the
second SE of a group appears in a cluster.

## Prerequisites

- **vCenter account.** The vCenter user in the credentials file needs permission to edit DRS
  rules in vCenter (Host > Inventory > Modify cluster). Usually a service account.
- **Python packages on the controller.** The script imports `pyVmomi` and `cryptography`. Before
  setting up the alert, check that both are available to ControlScripts on your controller (see
  [step 2](#2-add-the-controlscript)). Script will run on Avi 31.2.1 or higher, possibly older
  versions as well.
- **Network access.** The controller must be able to reach vCenter on port 443.
- **Controller cluster name.** Name the controller cluster after the controller's FQDN, in
  **Administration > Controller > Nodes > Edit**. The default name (such as `cluster-0-1`)
  works too, but then that's what appears in the rule name. Renaming the cluster later changes
  the rule name, so the script starts a new rule rather than adding to the old one.
- **Avi permissions.** The user the ControlScript runs as must be able to:
  - read fileobjects (`PERMISSION_FILE_OBJECT`)
  - read Service Engines and SE groups (`PERMISSION_SE` and `PERMISSION_SEGROUP`), to list
    the SEs in the group
  - read the controller cluster (`PERMISSION_CONTROLLER`), to get its name for the rule name
  - read certificates, including the private key (the script requests it with `export_key=true`)

The UI paths below follow the standard Avi Load Balancer layout. Menu names move slightly
between releases, so check them against the docs for your controller version.

## 1. Encrypt the credentials file and upload it to the controller

### 1a. Create the certificate in Avi

The credentials file is encrypted with the public key of an Avi certificate (an
`sslkeyandcertificate` object). Only someone holding that certificate's private key can decrypt
it, and the key never leaves the controller.

1. Go to **Templates > Security > SSL/TLS Certificates**.
2. Click **Create > Application Certificate**.
3. Set **Name** to `controlscript-cert`. This is the script's default name; if you pick another,
   change `DEFAULT_CREDENTIALS_CERT` in the script to match.
4. Set **Type** to **Self Signed**. Fill in a Common Name (for example `controlscript`), choose
   **RSA** or **EC**, and click **Save**. You can also **Import** a certificate and key you
   already have, such as one from your certificate management platform.
5. Find the certificate in the list and click its **Export** icon. Copy the **Certificate** text
   (not the key) into a file named `controlscript_cert.pem`.

**Note:** You do not strictly need to create a new cert/key for this workflow. You may use an
existing RSA or EC cert from the controller, so long as you have access to the key. Just ensure
that you update the value of `DEFAULT_CREDENTIALS_CERT` on line 141 of the script to match the
name of the `sslkeyandcertificate` object which you intend to use.

### 1b. Encrypt the file

Create `credentials.json`:

```json
{
  "name": "vCenter credentials for DRS rule updates.",
  "vcenter": "vcenter.example.com",
  "username": "myaviserviceaccountname@vsphere.local",
  "password": "myserviceaccountpassword"
}
```

Encrypt it with the certificate, using AES-256:

```sh
openssl cms -encrypt -in credentials.json -out credentials.json.enc \
    -recip controlscript_cert.pem -aes256
```

The script accepts openssl's default S/MIME output, and also `-outform PEM` and `-outform DER`.

Next, delete the plain-text copy:

```sh
shred -u credentials.json   # or rm, on filesystems where shred doesn't help
```

### 1c. Upload it as a fileobject

The upload goes through the REST API (`POST /api/fileobject/upload`). The script downloads the
fileobject named `vcentercredentials.json.enc` by default, which is the value of
`DEFAULT_CREDENTIALS_FILENAME` in the script. Upload the local `credentials.json.enc` under
that name. To use a different name, change `DEFAULT_CREDENTIALS_FILENAME` to the fileobject's
full name.

```sh
CONTROLLER=avi-controller.example.com
AVI_VERSION=32.1.4            # your controller's version
AVI_USER=admin

# Log in; this saves the session and CSRF cookies.
read -rsp "Avi password: " AVI_PASS; echo
curl -sk -c cookies.txt -H 'Content-Type: application/json' \
    -d "{\"username\": \"$AVI_USER\", \"password\": \"$AVI_PASS\"}" \
    "https://$CONTROLLER/login" -o /dev/null
unset AVI_PASS
CSRF=$(awk '$6 == "csrftoken" {print $7}' cookies.txt)

# Upload the encrypted file.
curl -sk -b cookies.txt \
    -H "X-CSRFToken: $CSRF" \
    -H "Referer: https://$CONTROLLER/" \
    -H "X-Avi-Version: $AVI_VERSION" \
    -F name=vcentercredentials.json.enc \
    -F type=OTHER_FILE_TYPES \
    -F file=@credentials.json.enc \
    "https://$CONTROLLER/api/fileobject/upload"

# Check that it's there.
curl -sk -b cookies.txt -H "X-Avi-Version: $AVI_VERSION" \
    "https://$CONTROLLER/api/fileobject?name=vcentercredentials.json.enc"

rm cookies.txt
```

Don't set `restrict_download=true` on this fileobject. The script needs to download it from
`/api/fileobject/<uuid>/download`.

To change the credentials later, encrypt a new file, upload it under the same name
(`-F allow_update=true` on controllers that support it, or delete the old fileobject first),
and delete the plain-text copy.

## 2. Add the ControlScript

Edit the settings near the top of the script before uploading it. An alert-triggered
ControlScript receives only the alert JSON, so it can't be given command-line options or
environment variables.

| Setting | Default | Meaning |
|---|---|---|
| `DEFAULT_CREDENTIALS_CERT` | `controlscript-cert` | Name of the Avi certificate from step 1a |
| `DEFAULT_CREDENTIALS_FILENAME` | `vcentercredentials.json.enc` | Full name of the fileobject from step 1c |
| `VERIFY_VCENTER_CERT` | `False` | Set to `True` to verify vCenter's certificate |

vCenter certificate verification is off by default because vCenter's certificate is usually
signed by its own CA (VMCA), which the controller doesn't trust.

Then add the script:

1. Go to **Templates > Scripts > ControlScripts**.
2. Click **Create**.
3. Set **Name** to `se-antiaffinity`.
4. Click **Import File** and choose `avi-controlscript-se-antiaffinitygroup.py`, or paste the
   script into the editor.
5. Click **Save**.

## 3. Create the alert action

1. Go to **Operations > Alerts > Alert Actions**.
2. Click **Create**.
3. Set **Name** to `se-antiaffinity-action`.
4. Set **Alert Level** to **Low**. This only sets the severity of the alert; the alert config
   in step 4 also has a level.
5. Leave **Only Generate Alert** off. If it's on, the action records the alert but runs nothing.
6. For **ControlScript**, select `se-antiaffinity`.
7. Optionally, add **Email**, **Syslog** or **SNMP Trap** notifications as well.
8. Click **Save**.

## 4. Create the alert config for CREATED_SE

The alert config must raise **one alert, and so one run of the script, for every Service
Engine created**. Each run handles one SE: the script processes only the first `CREATED_SE`
event in the alert it receives. The settings below that make this happen are **Throttle Alert**,
**Number of Occurrences** and the object instance.

1. Go to **Operations > Alerts > Alert Config**.
2. Click **Create**.
3. Under **General**:
   - **Name:** `se-created-antiaffinity`
   - **Enable Alert Trigger:** on
   - **Source:** **Event Logs**
4. Under **Conditions**:
   - **Throttle Alert:** `0` seconds. This is required. The throttle stops further alerts from
     this config for that many seconds after one is raised. With the default (several
     minutes), SEs created during that time, such as during a scale-out, wouldn't get an
     alert, and so wouldn't be added to the rule. `0` turns throttling off, so each event
     raises its own alert.
   - **Object:** **None** (the `CREATED_SE` event is raised on the SE group). Leave the
     instance empty so the alert fires for SEs in **every** SE group. If you pick one group,
     SEs created in other groups won't run the script.
   - **Number of Occurrences:** `1`, so a single `CREATED_SE` event raises the alert. If a time
     window (**Within**) is shown, leave it at its default; it doesn't matter with one
     occurrence.
   - **Category:** **Real Time**
   - **Event:** under **Event Occurs**, add `CREATED_SE` (shown in the UI as "Created SE"), and
     no other events.
5. Under **Actions**, set **Alert Action** to `se-antiaffinity-action`.
6. Click **Save**.

To check the saved settings, open the alert config in the UI, or read it through the API. The
`throttle` field should be `0`, and `alert_rule.sys_event_rule` should contain
`CREATED_SE`:

```sh
curl -sk -b cookies.txt -H "X-Avi-Version: $AVI_VERSION" \
    "https://$CONTROLLER/api/alertconfig?name=se-created-antiaffinity"
```

Each alert's JSON includes `"throttle_count"`, the number of alerts suppressed by throttling
before this one. It should always be `0`. If it's higher, throttling is still on, and some SEs
weren't added to the rule until the next alert for their SE group.

## Verifying

- Scale out an SE group, or create a virtual service that needs a new SE.
- **Operations > Alerts > All Alerts** should list a `se-created-antiaffinity` alert. Opening it
  shows the ControlScript's output: log lines such as `Adding avi-se-abcde to existing rule
  'avi_se_antiaffinity_avi.example.com_Default-Cloud_Default-Group' on cluster 'cl1'`, or an
  error. Before that, the line `Avi API lists N SE(s) in SE group '…'` shows which SEs the
  script counted. Warnings name any of the group's SEs that have no VM in vCenter, or whose VM
  is in another cluster.
- Create several SEs close together (for example, scale an SE group out by two or more). You
  should see **one alert per SE**, each naming a different SE in its event details. If there
  are fewer alerts than SEs, re-check **Throttle Alert** in
  [step 4](#4-create-the-alert-config-for-created_se).
- In vCenter, open the cluster's **Configure > VM/Host Rules**. You should see the
  `avi_se_antiaffinity_<controller FQDN>_<Avi cloud name>_<SE group name>` rule with the SE VMs
  in it.
- The first SE created in a group will **not** cause a DRS rule to be created. vCenter requires
  anti-affinity rules to contain two or more valid VMs, so the rule is only created once the
  group has two SEs in the cluster.
- If SEs are deleted from the controller, their VMs are removed from the inventory, and so from
  the DRS rule. When fewer than two VMs remain in the rule, the rule itself is deleted. vCenter
  does this, not the script.

## Local testing and development

Install dependencies with [Poetry](https://python-poetry.org/):

```sh
poetry install
```

You can run the script from a workstation with a saved alert, a local credentials file and
`--dry-run`. These commands **log in to the real vCenter** named in the credentials file and
read its VMs and rules; `--dry-run` only stops the script from changing the rule:

```sh
# Plain-text credentials file (testing only)
poetry run python avi-controlscript-se-antiaffinitygroup.py --event-file event_data.json \
    --credentials-file credentials.json --controller-fqdn avi.example.com \
    --se-group-members slb-se-eyiec slb-se-abcde --dry-run

# Encrypted credentials file, decrypted with a local copy of the key and certificate
poetry run python avi-controlscript-se-antiaffinitygroup.py --event-file event_data.json \
    --credentials-file credentials.json.enc \
    --key-file controlscript_key.pem --cert-file controlscript_cert.pem \
    --controller-fqdn avi.example.com \
    --se-group-members slb-se-eyiec slb-se-abcde --dry-run
```

`--se-group-members` and `--controller-fqdn` replace the Avi API lookups, which only work on
the controller. `--se-group-members` lists the SE names in the SE group: list the new SE and at
least one other, or the script stops before changing the rule. `--controller-fqdn` is the
controller name to use in the rule name.

Other options: `-se`/`-seg`/`--cloud-name` override the SE name, SE group and cloud name from
the event. Outside the controller, `--credentials-cert`/`AVI_CREDENTIALS_CERT` and
`--fileobject-download-path`/`FILEOBJECT_DOWNLOAD_PATH` override the settings above. Run
`--help` for the full list.

Run the unit tests, with coverage. No controller or vCenter is needed:

```sh
poetry run pytest --cov --cov-branch --cov-report=term-missing
```

The tests never contact a real system. vCenter and the Avi API are mocks, and any attempt to
open a network connection fails the test. To run the dry-run commands above against a mocked
vCenter, with `event_data.json` and throwaway test credentials, run:

```sh
poetry run pytest tests/test_dry_run.py -v
```
