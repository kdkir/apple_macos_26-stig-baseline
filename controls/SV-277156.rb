control 'SV-277156' do
  title 'The macOS system must set minimum password lifetime to 24 hours.'
  desc 'The macOS must be configured to enforce a minimum password lifetime limit of 24 hours.

This rule discourages users from cycling through their previous passwords to get back to a preferred one.

Note: The guidance for password-based authentication in NIST 800-53 (Rev 5) and NIST 800-63B states that complexity rules must be organizationally defined. The values defined are based on common complexity values, but each organization may define its own password complexity rules.'
  desc 'check', %q(Verify the macOS system is configured to set minimum password lifetime to 24 hours with the following command:

/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributeMinimumLifetimeHours"]/following-sibling::integer[1]/text()' - | /usr/bin/awk '{ if ($1 >= 24 ) {print "pass"} else {print "fail"}}'

If the result is not "pass", this is a finding.)
  desc 'fix', 'Configure the macOS system to set minimum password lifetime to 24 hours.

This setting may be enforced using local policy.

To set local policy to require a minimum password lifetime, edit the current password policy to contain the following <dict> within the "policyCategoryPasswordContent":

[source,xml]
----
<dict>
<key>policyContent</key>
<string>policyAttributeLastPasswordChangeTime &lt; policyAttributeCurrentTime - (policyAttributeMinimumLifetimeHours * 60 * 60)</string>
<key>policyIdentifier</key>
<string>Minimum Password Lifetime</string>
<key>policyParameters</key>
<dict>
<key>policyAttributeMinimumLifetimeHours</key>
<integer>24</integer>
</dict>
</dict>
----
After saving the file and exiting to the command prompt, run the following command to load the new policy file, substituting the path to the file in place of "$pwpolicy_file".

[source,bash]
----
/usr/bin/pwpolicy setaccountpolicies $pwpolicy_file
----'
  impact 0.5
  tag check_id: 'C-81311r1149370_chk'
  tag severity: 'medium'
  tag gid: 'V-277156'
  tag rid: 'SV-277156r1149412_rule'
  tag stig_id: 'APPL-26-003070'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag fix_id: 'F-81216r1148919_fix'
  tag 'documentable'
  tag cci: ['CCI-004066']
  tag nist: ['IA-5 (1) (h)']

  describe macos_pwpolicy do
    its('minimum_lifetime_hours') { should_not be_empty }
    its('minimum_lifetime_hours') { should all be >= 24 }
  end
end
