control 'SV-277122' do
  title "The macOS system must secure users' home folders."
  desc "The system must be configured to prevent access to other users' home folders.

The default behavior of macOS is to allow all valid users access to the top level of every other user's home folder while restricting access only to the Apple default folders within.

"
  desc 'check', 'Verify the macOS system is configured so that permissions are set correctly on user home directories with the following command:

/usr/bin/find /System/Volumes/Data/Users -mindepth 1 -maxdepth 1 -type d ! \\( -perm 700 -o -perm 711 \\) | /usr/bin/grep -v "Shared" | /usr/bin/grep -v "Guest" | /usr/bin/wc -l | /usr/bin/xargs

If the result is not "0", this is a finding.'
  desc 'fix', %q(Configure the macOS system to set the appropriate permissions for each user on the system with the following command:

IFS=$'\n'
for userDirs in $( /usr/bin/find /System/Volumes/Data/Users -mindepth 1 -maxdepth 1 -type d ! \( -perm 700 -o -perm 711 \\) | /usr/bin/grep -v "Shared" | /usr/bin/grep -v "Guest" ); do
/bin/chmod og-rwx "$userDirs"
done
unset IFS)
  impact 0.5
  tag check_id: 'C-81277r1148816_chk'
  tag severity: 'medium'
  tag gid: 'V-277122'
  tag rid: 'SV-277122r1148818_rule'
  tag stig_id: 'APPL-26-002068'
  tag gtitle: 'SRG-OS-000480-GPOS-00230'
  tag fix_id: 'F-81182r1148817_fix'
  tag satisfies: ['SRG-OS-000480-GPOS-00230', 'SRG-OS-000480-GPOS-00228']
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
