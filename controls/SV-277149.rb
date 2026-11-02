control 'SV-277149' do
  title 'The macOS system must remove password hints from user accounts.'
  desc 'User accounts must not contain password hints.

Password hints leak information about passwords in use and can lead to loss of confidentiality.'
  desc 'check', %q(Verify the macOS system is configured to remove password hints from user accounts with the following command:

HINT=$(/usr/bin/dscl . -list /Users hint | /usr/bin/awk '{ print $2 }')

if [ -z "$HINT" ]; then
echo "PASS"
else
echo "FAIL"
fi

If the result is not "PASS", this is a finding.)
  desc 'fix', "Configure the macOS system to remove password hints from user accounts with the following command:

for u in $(/usr/bin/dscl . -list /Users UniqueID | /usr/bin/awk '$2 > 500 {print $1}'); do
/usr/bin/dscl . -delete /Users/$u hint
done"
  impact 0.5
  tag check_id: 'C-81304r1148897_chk'
  tag severity: 'medium'
  tag gid: 'V-277149'
  tag rid: 'SV-277149r1148899_rule'
  tag stig_id: 'APPL-26-003014'
  tag gtitle: 'SRG-OS-000079-GPOS-00047'
  tag fix_id: 'F-81209r1148898_fix'
  tag 'documentable'
  tag cci: ['CCI-000206']
  tag nist: ['IA-6']
end
