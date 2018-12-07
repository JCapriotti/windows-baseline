# encoding: utf-8

title 'Security Options'

control 'accounts-block-microsoft-accounts' do
  title "(L1) Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can\'t add or log on with Microsoft accounts'"
  tag cis: ['windows_2016_1607:2.3.1.2']
  describe registry_key('HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should exist }
    its('NoConnectedUser') { should eq 3 }
  end
end

control 'force-audit-policy-subcategory-settings' do
  title "(L1) Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'"
  tag cis: ['windows_2016_1607:2.3.2.1']
  describe registry_key('HKLM\System\CurrentControlSet\Control\Lsa') do
    it { should exist }
    its('SCENoApplyLegacyAuditPolicy') { should eq 1 }
  end
end

control 'interactive-logon-do-not-display-last-user-name' do
  title "(L1) Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'"
  tag cis: ['windows_2016_1607:2.3.7.1']
  describe registry_key('HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should exist }
    its('DontDisplayLastUserName') { should eq 1 }
  end
end

control 'interactive-logon-machine-inactivity-limit' do
  title "(L1) Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'"
  tag cis: ['windows_2016_1607:2.3.7.4']
  describe registry_key('HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should exist }
    its('InactivityTimeoutSecs') { should eq 900 }
  end
end

control 'interactive-logon-smart-card-removal-behavior' do
  title "(L1) Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher"
  tag cis: ['windows_2016_1607:2.3.7.9']
  describe registry_key('HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon') do
    it { should exist }
    its('ScRemoveOption') { should be_in [1, 2, 3] }
  end
end

control 'microsoft-network-client-digitally-sign-communications' do
  title "(L1) Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'"
  tag cis: ['windows_2016_1607:2.3.8.1']
  describe registry_key('HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters') do
    it { should exist }
    its('RequireSecuritySignature') { should eq 1 }
  end
end

control 'microsoft-network-server-digitally-sign-communications-always' do
  title "(L1) Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'"
  tag cis: ['windows_2016_1607:2.3.9.2']
  describe registry_key('HKLM\System\CurrentControlSet\Services\LanManServer\Parameters') do
    it { should exist }
    its('RequireSecuritySignature') { should eq 1 }
  end
end

control 'microsoft-network-server-digitally-sign-communications-if-client-agrees' do
  title "(L1) Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'"
  tag cis: ['windows_2016_1607:2.3.9.3']
  describe registry_key('HKLM\System\CurrentControlSet\Services\LanManServer\Parameters') do
    it { should exist }
    its('EnableSecuritySignature') { should eq 1 }
  end
end

control 'microsoft-network-server-server-spn-target-name' do
  title "(L1) Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher"
  tag cis: ['windows_2016_1607:2.3.9.5']
  describe registry_key('HKLM\System\CurrentControlSet\Services\LanManServer\Parameters') do
    it { should exist }
    its('SMBServerNameHardeningLevel') { should eq 1 }
  end
end
 
control 'network-access-restrict-clients-allowed' do
  title "(L1) Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'"
  tag cis: ['windows_2016_1607:2.3.10.10']
  describe registry_key('HKLM\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should exist }
    its('RestrictRemoteSam') { should eq 'O:BAG:BAD:(A;;RC;;;BA)' }
  end
end
 
control 'network-access-shares-that-can-be-accessed-anonymously' do
  title "(L1) Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'"
  tag cis: ['windows_2016_1607:2.3.10.11']
  describe registry_key('HKLM\System\CurrentControlSet\Services\LanManServer\Parameters') do
    it { should exist }
    its('NullSessionShares') { should eq [''] }
  end
end

control 'network-security-allow-local-system-to-use-computer-identity' do
  title "(L1) Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'"
  tag cis: ['windows_2016_1607:2.3.11.1']
  describe registry_key('HKLM\System\CurrentControlSet\Control\Lsa') do
    it { should exist }
    its('UseMachineId') { should eq 1 }
  end
end

control 'network-security-allow-localsystem-null-session' do
  title "(L1) Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'"
  tag cis: ['windows_2016_1607:2.3.11.2']
  describe registry_key('HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0') do
    it { should exist }
    its('AllowNullSessionFallback') { should eq 0 }
  end
end

control 'network-security-allow-PKU2U-authentication' do
  title "(L1) Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'"
  tag cis: ['windows_2016_1607:2.3.11.3']
  describe registry_key('HKLM\System\CurrentControlSet\Control\Lsa\pku2u') do
    it { should exist }
    its('AllowOnlineID') { should eq 0 }
  end
end

control 'network-security-configure-encryption-types' do
  title "(L1) Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'"
  tag cis: ['windows_2016_1607:2.3.11.4']
  describe registry_key('HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters') do
    it { should exist }
    its('SupportedEncryptionTypes') { should eq 2147483640 }
  end
end

# These are in access_config:
# 2.3.11.7
# 2.3.11.9
# 2.3.11.10
