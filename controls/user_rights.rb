# encoding: utf-8

title 'User Rights Assignment'

sid_no_one              = 'S-1-0-0'
sid_authenticated_users = 'S-1-5-11'
sid_administrators      = 'S-1-5-32-544'
sid_users               = 'S-1-5-32-545'
sid_guests              = 'S-1-5-32-546'


control 'cis-access-cred-manager-2.2.1' do
  impact 0.7
  title '2.2.1 Set Access Credential Manager as a trusted caller to No One'
  desc 'Set Access Credential Manager as a trusted caller to No One'
  tag cis: ['windows_2016_1607:2.2.1']
  describe security_policy do
    its('SeTrustedCredManAccessPrivilege') { should eq [sid_no_one] }
  end
end

control 'cis-network-access-2.2.3' do
  impact 0.7
  title '(L1) Ensure "Access this computer from the network" is set to "Administrators, Authenticated Users" (MS only)'
  tag cis: ['windows_2016_1607:2.2.3']
  describe security_policy do
    its('SeNetworkLogonRight') { should include sid_administrators}
    its('SeNetworkLogonRight') { should include sid_authenticated_users}
  end
end

control 'cis-act-as-os-2.2.3' do
  impact 0.7
  title '2.2.3 Set Act as part of the operating system to No One'
  desc 'Set Act as part of the operating system to No One'
  describe security_policy do
    its('SeTcbPrivilege') { should eq [sid_no_one] }
  end
end

control 'cis-add-workstations-2.2.4' do
  impact 0.7
  title '2.2.4 Set Add workstations to domain to Administrators'
  desc 'Set Add workstations to domain to Administrators'
  describe security_policy do
    its('SeMachineAccountPrivilege') { should eq [sid_administrators] }
  end
end

control 'cis-adjust-memory-quotas-2.2.5' do
  impact 0.7
  title '2.2.5 Set Adust memory quotas for a process to Administrators, LOCAL SERVICE, NETWORK SERVICE'
  desc 'Set Adust memory quotas for a process to Administrators, LOCAL SERVICE, NETWORK SERVICE'
  describe security_policy do
    its('SeIncreaseQuotaPrivilege') { should include 'S-1-5-19' }
    its('SeIncreaseQuotaPrivilege') { should include 'S-1-5-20' }
    its('SeIncreaseQuotaPrivilege') { should include sid_administrators }
  end
end

control 'cis-allow-log-on-locally' do
  impact 0.7
  title '(L1) Ensure "Allow log on locally" is set to "Administrators"'
  tag cis: ['windows_2016_1607:2.2.7']
  describe security_policy do
    its('SeInteractiveLogonRight') { should eq [sid_administrators] }
  end
end

control 'cis-back-up-files-and-directories' do
  impact 0.7
  title '(L1) Ensure "Back up files and directories" is set to "Administrators"'
  tag cis: ['windows_2016_1607:2.2.10']
  describe security_policy do
    its('SeBackupPrivilege') { should eq [sid_administrators] }
  end
end

control 'deny-log-on-as-a-batch-job' do
  impact 0.7
  title '(L1) Ensure "Deny log on as a batch job" to include "Guests"'
  tag cis: ['windows_2016_1607:2.2.22']
  describe security_policy do
    its('SeDenyBatchLogonRight') { should include sid_guests }
  end
end

control 'deny-log-on-as-a-service' do
  impact 0.7
  title '(L1) Ensure "Deny log on as a service" to include "Guests"'
  tag cis: ['windows_2016_1607:2.2.23']
  describe security_policy do
    its('SeDenyServiceLogonRight') { should include sid_guests }
  end
end

control 'deny-log-on-locally' do
  impact 0.7
  title '(L1) Ensure "Deny log on locally" to include "Guests"'
  tag cis: ['windows_2016_1607:2.2.24']
  describe security_policy do
    its('SeDenyInteractiveLogonRight') { should include sid_guests }
  end
end

control 'restore-files-and-directories' do
  impact 0.7
  title '(L1) Ensure "Restore files and directories" is set to "Administrators"'
  tag cis: ['windows_2016_1607:2.2.45']
  describe security_policy do
    its('SeRestorePrivilege') { should eq [sid_administrators] }
  end
end

control 'shut-down-the-system' do
  impact 0.7
  title '(L1) Ensure "Shut down the system" is set to "Administrators, Users"'
  tag cis: ['windows_2016_1607:2.2.46']
  describe security_policy do
    its('SeShutdownPrivilege') { should include sid_administrators }
    its('SeShutdownPrivilege') { should include sid_users }
  end
end
