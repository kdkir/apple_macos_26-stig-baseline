control 'SV-282964' do
  title 'The macOS system must be a version supported by the vendor.'
  desc 'Unsupported software and systems should not be used because fixes to newly identified bugs will not be implemented by the vendor. The lack of support can result in potential vulnerabilities.

Software and systems at unsupported servicing levels or releases will not receive security updates for new vulnerabilities, which leaves them subject to exploitation.

When maintenance updates and patches are no longer available, software is no longer considered supported and should be upgraded or decommissioned.'
  desc 'check', 'Verify the operating system version.

Click the Apple icon on the menu at the top left corner of the screen.
Select the "About This Mac" option.

If the operating system version is no longer supported by the vendor, this is a finding.'
  desc 'fix', 'Upgrade to a supported version of the operating system.'
  impact 0.7
  tag check_id: 'C-87526r1184569_chk'
  tag severity: 'high'
  tag gid: 'V-282964'
  tag rid: 'SV-282964r1184571_rule'
  tag stig_id: 'APPL-26-006000'
  tag gtitle: 'SRG-OS-000830-GPOS-00300'
  tag fix_id: 'F-87431r1184570_fix'
  tag 'documentable'
  tag cci: ['CCI-003376']
  tag nist: ['SA-22 a']
end
