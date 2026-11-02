control 'SV-277166' do
  title 'The macOS system must enforce FileVault.'
  desc 'The information system implements cryptographic mechanisms to protect the confidentiality and integrity of information stored on digital media during transport outside of controlled areas.

'
  desc 'check', %q(Verify the macOS system is configured to enforce FileVault with the following command:

dontAllowDisable=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('dontAllowFDEDisable').js
EOS
)
fileVault=$(/usr/bin/fdesetup status | /usr/bin/grep -c "FileVault is On.")
if [[ "$dontAllowDisable" == "true" ]] && [[ "$fileVault" == 1 ]]; then
  echo "1"
else
  echo "0"
fi

If the result is not "1", this is a finding.)
  desc 'fix', 'Refer to the FileVault supplemental to implement this rule. Configure the macOS system to enforce FileVault by installing the "com.apple.MCX" configuration profile.'
  impact 0.7
  tag check_id: 'C-81321r1148948_chk'
  tag severity: 'high'
  tag gid: 'V-277166'
  tag rid: 'SV-277166r1148950_rule'
  tag stig_id: 'APPL-26-005020'
  tag gtitle: 'SRG-OS-000185-GPOS-00079'
  tag fix_id: 'F-81226r1148949_fix'
  tag satisfies: ['SRG-OS-000185-GPOS-00079', 'SRG-OS-000404-GPOS-00183', 'SRG-OS-000405-GPOS-00184']
  tag 'documentable'
  tag cci: ['CCI-001199', 'CCI-002475', 'CCI-002476']
  tag nist: ['SC-28', 'SC-28 (1)', 'SC-28 (1)']
end
