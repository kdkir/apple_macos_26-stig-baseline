control 'SV-277138' do
  title 'The macOS system must disable Printer Sharing.'
  desc 'Printer Sharing must be disabled.'
  desc 'check', 'Verify the macOS system is configured to disable Printer Sharing with the following command:

/usr/sbin/cupsctl | /usr/bin/grep -c "_share_printers=0"

If the result is not "1", this is a finding.'
  desc 'fix', "Configure the macOS system to disable Printer Sharing with the following commands:

/usr/sbin/cupsctl --no-share-printers
/usr/bin/lpstat -p | awk '{print $2}'| /usr/bin/xargs -I{} lpadmin -p {} -o printer-is-shared=false"
  impact 0.5
  tag check_id: 'C-81293r1148864_chk'
  tag severity: 'medium'
  tag gid: 'V-277138'
  tag rid: 'SV-277138r1148866_rule'
  tag stig_id: 'APPL-26-002240'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-81198r1148865_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
