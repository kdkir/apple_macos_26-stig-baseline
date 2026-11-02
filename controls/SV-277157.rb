control 'SV-277157' do
  title 'The macOS system must disable accounts after 35 days of inactivity.'
  desc 'The macOS must be configured to disable accounts after 35 days of inactivity.

This rule prevents malicious users from employing unused accounts to gain access to the system while avoiding detection.

'
  desc 'check', %q(Verify the macOS system is configured to disable accounts after 35 days of inactivity with the following command:

/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributeInactiveDays"]/following-sibling::integer[1]/text()' -

If the result is not "35", this is a finding.)
  desc 'fix', 'Configure the macOS system to disable accounts after 35 days of inactivity with the following command:

This setting may be enforced using local policy.

To set local policy to disable an inactive user after 35 days, edit the current password policy to contain the following <dict> within the "policyCategoryAuthentication":

[source,xml]
----
<dict>
<key>policyContent</key>
<string>policyAttributeLastAuthenticationTime &gt; policyAttributeCurrentTime - (policyAttributeInactiveDays * 24 * 60 * 60)</string>
<key>policyIdentifier</key>
<string>Inactive Account</string>
<key>policyParameters</key>
<dict>
<key>policyAttributeInactiveDays</key>
<integer>35</integer>
</dict>
</dict>
----
After saving the file and exiting to the command prompt, run the following command to load the new policy file, substituting the path to the file in place of "$pwpolicy_file".

[source,bash]
----
/usr/bin/pwpolicy setaccountpolicies $pwpolicy_file
----'
  impact 0.5
  tag check_id: 'C-81312r1148921_chk'
  tag severity: 'medium'
  tag gid: 'V-277157'
  tag rid: 'SV-277157r1148923_rule'
  tag stig_id: 'APPL-26-003080'
  tag gtitle: 'SRG-OS-000118-GPOS-00060'
  tag fix_id: 'F-81217r1148922_fix'
  tag satisfies: ['SRG-OS-000118-GPOS-00060', 'SRG-OS-000590-GPOS-00110']
  tag 'documentable'
  tag cci: ['CCI-003627', 'CCI-003628']
  tag nist: ['AC-2 (3) (a)', 'AC-2 (3) (b)']
end
