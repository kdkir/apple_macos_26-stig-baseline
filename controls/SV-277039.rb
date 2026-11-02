control 'SV-277039' do
  title 'The macOS system must display the Standard Mandatory DoW Notice and Consent Banner at the login window.'
  desc 'Displaying a standardized and approved use notification before granting access to the operating system ensures that users are provided with privacy and security notification verbiage that is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via login interfaces with human users and are not required when such human interfaces do not exist.

The policy banner will show if a "PolicyBanner.rtf" or "PolicyBanner.rtfd" exists in the "/Library/Security" folder.

The banner must be formatted in accordance with DTM-08-060.

'
  desc 'check', %q(Verify the macOS system is configured to display a policy banner with the following command:

/bin/ls -ld /Library/Security/PolicyBanner.rtf* | /usr/bin/wc -l | /usr/bin/tr -d ' '

If the command does not return "1", this is a finding.

The banner text of the document must read:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

If the text is not worded exactly this way, this is a finding.)
  desc 'fix', 'Configure the macOS system to display a policy banner by creating an RTF file containing the required text. Name the file "PolicyBanner.rtfd" and place it in "/Library/Security/".

Update the permissions of the "/Library/Security/PolicyBanner.rtfd" file with the following command:

/usr/bin/sudo /bin/chmod 644 /Library/Security/PolicyBanner.rtfd'
  impact 0.5
  tag check_id: 'C-81194r1148567_chk'
  tag severity: 'medium'
  tag gid: 'V-277039'
  tag rid: 'SV-277039r1268215_rule'
  tag stig_id: 'APPL-26-000025'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag fix_id: 'F-81099r1148568_fix'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000024-GPOS-00007', 'SRG-OS-000228-GPOS-00088']
  tag 'documentable'
  tag cci: ['CCI-000048', 'CCI-000050', 'CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['AC-8 a', 'AC-8 b', 'AC-8 c 1', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 3']

  expected_banner = input('policy_banner_text').split.join(' ')
  banner_paths = %w[/Library/Security/PolicyBanner.rtf /Library/Security/PolicyBanner.rtfd].select { |p| file(p).exist? }

  describe 'Policy banner documents in /Library/Security' do
    subject { banner_paths }
    its('count') { should eq 1 }
  end

  unless banner_paths.empty?
    banner_text = command("/usr/bin/textutil -convert txt -stdout #{banner_paths.first}").stdout

    describe "The text of #{banner_paths.first} (whitespace-normalized)" do
      subject { banner_text.split.join(' ') }
      it { should eq expected_banner }
    end
  end
end
