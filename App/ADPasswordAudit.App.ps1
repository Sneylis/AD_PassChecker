#Requires -Version 5.1
<#
.SYNOPSIS
    Single WPF application for deploying and operating the AD password
    audit system. Three modes:
        * Setup Wizard  - first-time install on the audit station.
        * Control Panel - run audit / cleanup / retention manually.
        * Health Check  - status of Scheduled Tasks and last log tail.

.NOTES
    File is intentionally ASCII-only to avoid PS 5.1 encoding pitfalls
    (PS 5.1 reads .ps1 as Windows-1252 when no BOM is present).
#>

[CmdletBinding()]
param(
    [string] $ConfigPath = 'C:\ProgramData\ADPasswordAudit\audit.config.psd1'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:AppRoot    = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:RepoRoot   = Split-Path -Parent $script:AppRoot
$script:ConfigPath = $ConfigPath

foreach ($m in 'Logging','Config','Crypto','CleanupHelpers') {
    $path = Join-Path $script:RepoRoot "Common\$m.psm1"
    if (Test-Path -LiteralPath $path) { Import-Module $path -Force -ErrorAction SilentlyContinue }
}

# ============================================================
# XAML
# ============================================================
[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="AD Password Audit - Console"
        Width="1100" Height="780"
        WindowStartupLocation="CenterScreen"
        Background="#1E1E2E" Foreground="#CDD6F4" FontFamily="Segoe UI" FontSize="13">
  <Window.Resources>
    <Style TargetType="Button">
      <Setter Property="Background" Value="#45475A"/>
      <Setter Property="Foreground" Value="#CDD6F4"/>
      <Setter Property="BorderBrush" Value="#585B70"/>
      <Setter Property="Padding" Value="12,6"/>
      <Setter Property="MinWidth" Value="100"/>
      <Setter Property="Margin" Value="3"/>
    </Style>
    <Style TargetType="TextBox">
      <Setter Property="Background" Value="#313244"/>
      <Setter Property="Foreground" Value="#CDD6F4"/>
      <Setter Property="BorderBrush" Value="#585B70"/>
      <Setter Property="Padding" Value="6,3"/>
      <Setter Property="Margin" Value="3"/>
    </Style>
    <Style TargetType="PasswordBox">
      <Setter Property="Background" Value="#313244"/>
      <Setter Property="Foreground" Value="#CDD6F4"/>
      <Setter Property="BorderBrush" Value="#585B70"/>
      <Setter Property="Padding" Value="6,3"/>
      <Setter Property="Margin" Value="3"/>
    </Style>
    <Style TargetType="Label">
      <Setter Property="Foreground" Value="#CDD6F4"/>
      <Setter Property="Margin" Value="0,4,0,0"/>
    </Style>
    <Style TargetType="GroupBox">
      <Setter Property="Foreground" Value="#89B4FA"/>
      <Setter Property="Margin" Value="6"/>
      <Setter Property="Padding" Value="8"/>
    </Style>
    <Style TargetType="ComboBox">
      <Setter Property="Background" Value="#313244"/>
      <Setter Property="Foreground" Value="#CDD6F4"/>
      <Setter Property="Margin" Value="3"/>
    </Style>
    <Style TargetType="TabItem">
      <Setter Property="Background" Value="#313244"/>
      <Setter Property="Foreground" Value="#CDD6F4"/>
      <Setter Property="Padding" Value="14,6"/>
    </Style>
  </Window.Resources>

  <DockPanel>
    <Border DockPanel.Dock="Top" Background="#11111B" Padding="14,10">
      <StackPanel Orientation="Horizontal">
        <TextBlock Text="AD Password Audit" FontSize="20" FontWeight="Bold" Foreground="#89B4FA"/>
        <TextBlock x:Name="HeaderSubtitle" Text="  - setup and operations console"
                   FontSize="14" Foreground="#A6ADC8" VerticalAlignment="Bottom" Margin="6,0,0,3"/>
      </StackPanel>
    </Border>

    <TabControl x:Name="MainTabs" Background="#1E1E2E" BorderBrush="#45475A">

      <TabItem Header="  Setup Wizard  " x:Name="TabWizard">
        <Grid Margin="14">
          <Grid.RowDefinitions>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>

          <Border Grid.Row="0" Background="#181825" BorderBrush="#45475A" BorderThickness="1" Padding="14">
            <Grid x:Name="WizardPages">

              <StackPanel x:Name="Page0" Visibility="Visible">
                <TextBlock Text="Step 1 of 8 - Welcome and preflight" FontSize="16" Foreground="#89B4FA" Margin="0,0,0,10"/>
                <TextBlock TextWrapping="Wrap" Foreground="#CDD6F4" Margin="0,0,0,10">
This wizard deploys the AD password audit infrastructure on this audit station.
Before we start, I will check that the host is hardened.
                </TextBlock>
                <GroupBox Header="Preflight checks">
                  <StackPanel x:Name="PreflightList"/>
                </GroupBox>
                <Button x:Name="BtnRecheckPreflight" Content="Re-check" HorizontalAlignment="Left" Margin="0,8,0,0"/>
                <TextBlock x:Name="PreflightSummary" Margin="0,8,0,0" TextWrapping="Wrap"/>
              </StackPanel>

              <StackPanel x:Name="Page1" Visibility="Collapsed">
                <TextBlock Text="Step 2 of 8 - Domain controller and network" FontSize="16" Foreground="#89B4FA" Margin="0,0,0,10"/>
                <Label Content="DC FQDN or IP"/>
                <TextBox x:Name="TbDC" Text="dc01.corp.lab.local"/>
                <Label Content="Domain DNS name"/>
                <TextBox x:Name="TbDomain" Text="corp.lab.local"/>
                <Label Content="This audit station hostname (auto)"/>
                <TextBox x:Name="TbStation" IsReadOnly="True"/>
                <Label Content="UNC SMB share for IFM archive transfer"/>
                <TextBox x:Name="TbSmb" Text="\\fileserver\IFM-Exchange$"/>
                <StackPanel Orientation="Horizontal" Margin="0,10,0,0">
                  <Button x:Name="BtnTestDC"  Content="Test DC connection"/>
                  <Button x:Name="BtnTestSmb" Content="Test SMB share"/>
                </StackPanel>
                <TextBlock x:Name="DcTestResult" Margin="0,8,0,0" TextWrapping="Wrap"/>
              </StackPanel>

              <StackPanel x:Name="Page2" Visibility="Collapsed">
                <TextBlock Text="Step 3 of 8 - Service account (Backup Operator)" FontSize="16" Foreground="#89B4FA" Margin="0,0,0,10"/>
                <TextBlock TextWrapping="Wrap" Foreground="#A6ADC8" Margin="0,0,0,10">
This account will run Phase 1 (ntdsutil ifm) on the DC. Backup Operators membership is sufficient.
The password is stored in a local SecretStore (DPAPI per-machine, protected by BitLocker FDE).
                </TextBlock>
                <Label Content="Username (DOMAIN\sam or sam@domain)"/>
                <TextBox x:Name="TbSvcUser" Text="CORP\svc-adaudit"/>
                <Label Content="Password"/>
                <PasswordBox x:Name="PbSvcPass"/>
                <Button x:Name="BtnVerifyCred" Content="Verify credential (LDAP bind)" HorizontalAlignment="Left" Margin="0,10,0,0"/>
                <TextBlock x:Name="CredTestResult" Margin="0,8,0,0" TextWrapping="Wrap"/>
              </StackPanel>

              <StackPanel x:Name="Page3" Visibility="Collapsed">
                <TextBlock Text="Step 4 of 8 - Directories on the audit station" FontSize="16" Foreground="#89B4FA" Margin="0,0,0,10"/>
                <Grid>
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="220"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                  </Grid.ColumnDefinitions>
                  <Grid.RowDefinitions>
                    <RowDefinition/><RowDefinition/><RowDefinition/><RowDefinition/>
                  </Grid.RowDefinitions>
                  <Label Grid.Row="0" Grid.Column="0" Content="Work directory"/>
                  <TextBox Grid.Row="0" Grid.Column="1" x:Name="TbWorkDir"   Text="D:\AuditWork"/>
                  <Button  Grid.Row="0" Grid.Column="2" x:Name="BtnBrowseWork"   Content="..."  Width="40" Tag="TbWorkDir"/>
                  <Label Grid.Row="1" Grid.Column="0" Content="Log directory"/>
                  <TextBox Grid.Row="1" Grid.Column="1" x:Name="TbLogDir"    Text="C:\AuditLogs"/>
                  <Button  Grid.Row="1" Grid.Column="2" x:Name="BtnBrowseLog"    Content="..."  Width="40" Tag="TbLogDir"/>
                  <Label Grid.Row="2" Grid.Column="0" Content="Reports retention dir"/>
                  <TextBox Grid.Row="2" Grid.Column="1" x:Name="TbReportDir" Text="D:\AuditReports"/>
                  <Button  Grid.Row="2" Grid.Column="2" x:Name="BtnBrowseReport" Content="..."  Width="40" Tag="TbReportDir"/>
                  <Label Grid.Row="3" Grid.Column="0" Content="Attestations dir"/>
                  <TextBox Grid.Row="3" Grid.Column="1" x:Name="TbAttestDir" Text="C:\AuditLogs\Attestations"/>
                  <Button  Grid.Row="3" Grid.Column="2" x:Name="BtnBrowseAttest" Content="..."  Width="40" Tag="TbAttestDir"/>
                </Grid>
              </StackPanel>

              <StackPanel x:Name="Page4" Visibility="Collapsed">
                <TextBlock Text="Step 5 of 8 - HIBP dictionary" FontSize="16" Foreground="#89B4FA" Margin="0,0,0,10"/>
                <RadioButton x:Name="RbHibpDownload" Content="Download NTLM dictionary (haveibeenpwned-downloader.exe)" IsChecked="True" Foreground="#CDD6F4"/>
                <RadioButton x:Name="RbHibpExisting" Content="Use existing file" Foreground="#CDD6F4"/>
                <StackPanel x:Name="HibpExistingPanel" Margin="20,6,0,0" IsEnabled="False">
                  <Label Content="Path to hibp-ntlm.txt"/>
                  <Grid>
                    <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                    <TextBox x:Name="TbHibpPath" Grid.Column="0" Text="D:\HIBP\hibp-ntlm.txt"/>
                    <Button  x:Name="BtnBrowseHibp" Grid.Column="1" Content="..." Width="40" Tag="TbHibpPath"/>
                  </Grid>
                  <Label Content="SHA-256 (leave empty to recompute)"/>
                  <TextBox x:Name="TbHibpSha"/>
                </StackPanel>
                <StackPanel x:Name="HibpDownloadPanel" Margin="20,6,0,0">
                  <Label Content="Download to"/>
                  <Grid>
                    <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                    <TextBox x:Name="TbHibpDownloadDir" Grid.Column="0" Text="D:\HIBP"/>
                    <Button  x:Name="BtnBrowseHibpDl"   Grid.Column="1" Content="..." Width="40" Tag="TbHibpDownloadDir"/>
                  </Grid>
                  <TextBlock TextWrapping="Wrap" Foreground="#F9E2AF" Margin="0,6,0,0">
Size: ~30 GB. Download time depends on bandwidth (1-2h on 100 Mbps).
The downloader is fetched from the official GitHub Releases. Actual download starts on Install.
                  </TextBlock>
                </StackPanel>
              </StackPanel>

              <StackPanel x:Name="Page5" Visibility="Collapsed">
                <TextBlock Text="Step 6 of 8 - Email delivery (SMTP + S/MIME)" FontSize="16" Foreground="#89B4FA" Margin="0,0,0,10"/>
                <Grid>
                  <Grid.ColumnDefinitions><ColumnDefinition Width="200"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                  <Grid.RowDefinitions>
                    <RowDefinition/><RowDefinition/><RowDefinition/><RowDefinition/><RowDefinition/>
                  </Grid.RowDefinitions>
                  <Label Grid.Row="0" Grid.Column="0" Content="SMTP server"/>
                  <TextBox Grid.Row="0" Grid.Column="1" x:Name="TbSmtp" Text="smtp.corp.lab.local"/>
                  <Label Grid.Row="1" Grid.Column="0" Content="SMTP port"/>
                  <TextBox Grid.Row="1" Grid.Column="1" x:Name="TbSmtpPort" Text="25"/>
                  <Label Grid.Row="2" Grid.Column="0" Content="From address"/>
                  <TextBox Grid.Row="2" Grid.Column="1" x:Name="TbSmtpFrom" Text="ad-audit@corp.lab.local"/>
                  <Label Grid.Row="3" Grid.Column="0" Content="Recipients (comma separated)"/>
                  <TextBox Grid.Row="3" Grid.Column="1" x:Name="TbSmtpTo" Text="sec-ops@corp.lab.local"/>
                  <Label Grid.Row="4" Grid.Column="0" Content="S/MIME signing certificate"/>
                  <ComboBox Grid.Row="4" Grid.Column="1" x:Name="CbSmime"/>
                </Grid>
                <Button x:Name="BtnRefreshCerts" Content="Refresh certificate list" HorizontalAlignment="Left" Margin="0,8,0,0"/>
              </StackPanel>

              <StackPanel x:Name="Page6" Visibility="Collapsed">
                <TextBlock Text="Step 7 of 8 - Schedule and retention" FontSize="16" Foreground="#89B4FA" Margin="0,0,0,10"/>
                <Grid>
                  <Grid.ColumnDefinitions><ColumnDefinition Width="240"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                  <Grid.RowDefinitions>
                    <RowDefinition/><RowDefinition/><RowDefinition/>
                  </Grid.RowDefinitions>
                  <Label Grid.Row="0" Grid.Column="0" Content="Day of month (1-28)"/>
                  <TextBox Grid.Row="0" Grid.Column="1" x:Name="TbDay" Text="1"/>
                  <Label Grid.Row="1" Grid.Column="0" Content="Hour UTC (Phase 1 - DC)"/>
                  <TextBox Grid.Row="1" Grid.Column="1" x:Name="TbHourDC" Text="2"/>
                  <Label Grid.Row="2" Grid.Column="0" Content="Hour UTC (Orchestrator - station)"/>
                  <TextBox Grid.Row="2" Grid.Column="1" x:Name="TbHourStation" Text="3"/>
                </Grid>
                <Label Content="Report retention (days)"/>
                <TextBox x:Name="TbRetention" Text="5" Width="100" HorizontalAlignment="Left"/>
              </StackPanel>

              <StackPanel x:Name="Page7" Visibility="Collapsed">
                <TextBlock Text="Step 8 of 8 - Review and install" FontSize="16" Foreground="#89B4FA" Margin="0,0,0,10"/>
                <TextBlock TextWrapping="Wrap" Foreground="#A6ADC8" Margin="0,0,0,8">
The installer will: install tools (7-Zip, SDelete, DSInternals), import HIBP, create SecretStore with AES key, register Scheduled Tasks, write the config file, and produce a DC bootstrap zip.
                </TextBlock>
                <GroupBox Header="Summary">
                  <ScrollViewer Height="200" VerticalScrollBarVisibility="Auto">
                    <TextBox x:Name="TbReview" IsReadOnly="True" TextWrapping="Wrap"
                             Background="#11111B" BorderThickness="0" FontFamily="Consolas" FontSize="12"/>
                  </ScrollViewer>
                </GroupBox>
                <Button x:Name="BtnInstall" Content="INSTALL" HorizontalAlignment="Left" Margin="0,10,0,0"
                        Background="#A6E3A1" Foreground="#1E1E2E" FontWeight="Bold" Padding="20,8"/>
                <ProgressBar x:Name="PbInstall" Height="22" Margin="0,10,0,0" Minimum="0" Maximum="100"/>
                <TextBlock x:Name="LblInstall" Margin="0,4,0,4" Foreground="#A6ADC8"/>
                <ScrollViewer Height="180" VerticalScrollBarVisibility="Auto" Margin="0,4,0,0">
                  <TextBox x:Name="TbInstallLog" IsReadOnly="True" TextWrapping="NoWrap" AcceptsReturn="True"
                           Background="#11111B" BorderThickness="0" FontFamily="Consolas" FontSize="11"
                           Foreground="#A6E3A1"/>
                </ScrollViewer>
              </StackPanel>

            </Grid>
          </Border>

          <StackPanel Grid.Row="1" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,12,0,0">
            <TextBlock x:Name="LblWizardStep" Foreground="#A6ADC8" Margin="0,8,16,0"/>
            <Button x:Name="BtnBack" Content="&lt; Back"/>
            <Button x:Name="BtnNext" Content="Next &gt;"/>
          </StackPanel>
        </Grid>
      </TabItem>

      <TabItem Header="  Control Panel  " x:Name="TabControlPanel">
        <Grid Margin="14">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <StackPanel Grid.Row="0" Orientation="Horizontal">
            <Button x:Name="BtnRunAudit"   Content="Run audit now"
                    Background="#89B4FA" Foreground="#1E1E2E" FontWeight="Bold" Padding="16,8"/>
            <Button x:Name="BtnRunPhase5"  Content="Cleanup only (Phase 5)"/>
            <Button x:Name="BtnRunRetent"  Content="Retention sweep"/>
            <Button x:Name="BtnOpenReportDir" Content="Open reports folder"/>
            <Button x:Name="BtnCancelAudit" Content="Cancel" IsEnabled="False"/>
          </StackPanel>
          <ProgressBar Grid.Row="1" x:Name="PbAudit" Height="22" Margin="0,10,0,0" IsIndeterminate="False"/>
          <ScrollViewer Grid.Row="2" Margin="0,10,0,0" VerticalScrollBarVisibility="Auto">
            <TextBox x:Name="TbAuditLog" IsReadOnly="True" TextWrapping="NoWrap" AcceptsReturn="True"
                     Background="#11111B" BorderThickness="0" FontFamily="Consolas" FontSize="12"
                     Foreground="#CDD6F4"/>
          </ScrollViewer>
        </Grid>
      </TabItem>

      <TabItem Header="  Health Check  " x:Name="TabHealth">
        <Grid Margin="14">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="200"/>
          </Grid.RowDefinitions>
          <StackPanel Grid.Row="0" Orientation="Horizontal">
            <Button x:Name="BtnRefreshHealth" Content="Refresh"/>
            <Button x:Name="BtnOpenLogDir"    Content="Open log folder"/>
            <Button x:Name="BtnOpenAttest"    Content="Open attestations"/>
          </StackPanel>
          <Label Grid.Row="1" Content="Scheduled tasks:"/>
          <DataGrid Grid.Row="2" x:Name="DgTasks" AutoGenerateColumns="False" CanUserAddRows="False" IsReadOnly="True"
                    Background="#181825" Foreground="#CDD6F4" BorderBrush="#45475A" RowBackground="#181825"
                    AlternatingRowBackground="#1E1E2E" GridLinesVisibility="Horizontal" HeadersVisibility="Column">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Task"          Binding="{Binding TaskName}"   Width="240"/>
              <DataGridTextColumn Header="State"         Binding="{Binding State}"      Width="80"/>
              <DataGridTextColumn Header="Last run UTC"  Binding="{Binding LastRunTime}" Width="160"/>
              <DataGridTextColumn Header="Last result"   Binding="{Binding LastResult}" Width="140"/>
              <DataGridTextColumn Header="Next run UTC"  Binding="{Binding NextRunTime}" Width="160"/>
            </DataGrid.Columns>
          </DataGrid>
          <Label Grid.Row="3" Content="Latest orchestrator run:"/>
          <ScrollViewer Grid.Row="4" VerticalScrollBarVisibility="Auto">
            <TextBox x:Name="TbHealthLog" IsReadOnly="True" TextWrapping="NoWrap" AcceptsReturn="True"
                     Background="#11111B" BorderThickness="0" FontFamily="Consolas" FontSize="12"
                     Foreground="#A6ADC8"/>
          </ScrollViewer>
        </Grid>
      </TabItem>

    </TabControl>
  </DockPanel>
</Window>
'@

# ============================================================
# Parse XAML, collect named controls
# ============================================================
$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)
$ctl    = @{}
$xaml.SelectNodes('//*[@*[local-name()="Name"]]') | ForEach-Object {
    $name = $_.GetAttribute('Name','http://schemas.microsoft.com/winfx/2006/xaml')
    if ($name) { $ctl[$name] = $window.FindName($name) }
}

# ============================================================
# State
# ============================================================
$script:WizardPage = 0
$script:WizardMax  = 7
$script:UiSync     = [System.Collections.Hashtable]::Synchronized(@{})
$script:UiSync.Lines    = New-Object System.Collections.Concurrent.ConcurrentQueue[string]
$script:UiSync.Status   = 'idle'
$script:UiSync.Progress = 0
$script:RunSpace   = $null
$script:RunPS      = $null

# ============================================================
# UI helpers
# ============================================================
function Set-WizardPage {
    param([int] $Index)
    if ($Index -lt 0)                 { $Index = 0 }
    if ($Index -gt $script:WizardMax) { $Index = $script:WizardMax }
    $script:WizardPage = $Index
    for ($i = 0; $i -le $script:WizardMax; $i++) {
        $page = $ctl["Page$i"]
        if ($page) {
            if ($i -eq $Index) { $page.Visibility = 'Visible' } else { $page.Visibility = 'Collapsed' }
        }
    }
    $ctl.LblWizardStep.Text = ('Step {0}/{1}' -f ($Index + 1), ($script:WizardMax + 1))
    if ($Index -gt 0) { $ctl.BtnBack.IsEnabled = $true } else { $ctl.BtnBack.IsEnabled = $false }
    if ($Index -eq $script:WizardMax) {
        $ctl.BtnNext.Content = 'Finish'
        Update-Review
    } else {
        $ctl.BtnNext.Content = 'Next >'
    }
}

function Add-PreflightItem {
    param([string] $Name, [bool] $Ok, [string] $Detail)
    $sp = New-Object System.Windows.Controls.StackPanel
    $sp.Orientation = 'Horizontal'
    $sp.Margin = '0,3,0,3'

    $tbIcon = New-Object System.Windows.Controls.TextBlock
    if ($Ok) {
        $tbIcon.Text = 'OK'
        $tbIcon.Foreground = 'LightGreen'
    } else {
        $tbIcon.Text = 'X'
        $tbIcon.Foreground = '#F38BA8'
    }
    $tbIcon.FontWeight = 'Bold'
    $tbIcon.Width = 26
    $sp.Children.Add($tbIcon) | Out-Null

    $tbName = New-Object System.Windows.Controls.TextBlock
    $tbName.Text  = $Name
    $tbName.Width = 250
    $sp.Children.Add($tbName) | Out-Null

    $tbDet = New-Object System.Windows.Controls.TextBlock
    $tbDet.Text         = $Detail
    $tbDet.Foreground   = '#A6ADC8'
    $tbDet.TextWrapping = 'Wrap'
    $sp.Children.Add($tbDet) | Out-Null

    $ctl.PreflightList.Children.Add($sp) | Out-Null
}

function Invoke-Preflight {
    $ctl.PreflightList.Children.Clear()
    $allOk = $true

    # Admin
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    $detail = 'OK'
    if (-not $isAdmin) { $detail = 'Restart as Administrator.' ; $allOk = $false }
    Add-PreflightItem -Name 'Local Administrator' -Ok $isAdmin -Detail $detail

    # OS
    $os = (Get-CimInstance Win32_OperatingSystem)
    $osOk = ([int]$os.BuildNumber -ge 17763)
    Add-PreflightItem -Name 'Windows Server 2019+' -Ok $osOk -Detail $os.Caption

    # PS
    $psOk = $PSVersionTable.PSVersion -ge [Version]'5.1'
    Add-PreflightItem -Name 'PowerShell 5.1+' -Ok $psOk -Detail "$($PSVersionTable.PSVersion)"

    # BitLocker
    $blOk = $false
    $blDetail = ''
    try {
        $bl = Get-BitLockerVolume -ErrorAction Stop |
              Where-Object { $_.MountPoint -match '^[A-Z]:$' }
        $bad = $bl | Where-Object { $_.ProtectionStatus -ne 'On' -or $_.VolumeStatus -ne 'FullyEncrypted' }
        if ($bl.Count -gt 0 -and $bad.Count -eq 0) {
            $blOk = $true
            $blDetail = "$($bl.Count) volumes FullyEncrypted"
        } else {
            $names = ($bad | ForEach-Object { $_.MountPoint }) -join ', '
            $blDetail = "Not encrypted: $names"
        }
    } catch {
        $blDetail = "Get-BitLockerVolume: $($_.Exception.Message)"
    }
    if (-not $blOk) { $allOk = $false }
    Add-PreflightItem -Name 'BitLocker FDE on all volumes' -Ok $blOk -Detail $blDetail

    # Pagefile
    $pfOk = $false
    $pfDetail = ''
    try {
        $pf = Get-CimInstance -ClassName Win32_PageFileSetting -ErrorAction SilentlyContinue
        if (-not $pf) { $pfOk = $true; $pfDetail = 'OK (off)' }
        else { $pfDetail = "Active: $($pf.Name)" }
    } catch { $pfDetail = $_.Exception.Message }
    if (-not $pfOk) { $allOk = $false }
    Add-PreflightItem -Name 'Pagefile disabled' -Ok $pfOk -Detail $pfDetail

    # Crash dump
    $cdOk = $false
    $cdDetail = ''
    try {
        $cc = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -ErrorAction SilentlyContinue
        if (-not $cc) { $cdOk = $true; $cdDetail = 'registry key missing - OK' }
        elseif ($cc.CrashDumpEnabled -eq 0) { $cdOk = $true; $cdDetail = 'OK (disabled)' }
        else { $cdDetail = "CrashDumpEnabled=$($cc.CrashDumpEnabled)" }
    } catch { $cdDetail = $_.Exception.Message }
    Add-PreflightItem -Name 'Crash dump disabled' -Ok $cdOk -Detail $cdDetail

    # RSAT
    $rsat = Get-Module -ListAvailable -Name ActiveDirectory
    $rsatDetail = 'will be installed during Install step'
    if ($rsat) { $rsatDetail = 'present' }
    Add-PreflightItem -Name 'RSAT ActiveDirectory module' -Ok ([bool]$rsat) -Detail $rsatDetail

    if ($allOk) {
        $ctl.PreflightSummary.Text = 'All required checks passed - you can continue.'
        $ctl.PreflightSummary.Foreground = 'LightGreen'
    } else {
        $ctl.PreflightSummary.Text = 'Some required checks failed. You can move on, but Install will refuse to deploy components until the host is hardened.'
        $ctl.PreflightSummary.Foreground = '#F9E2AF'
    }
}

function Get-WizardModel {
    $rec = ($ctl.TbSmtpTo.Text -split '[,;]') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    $smimeTp = $null
    if ($ctl.CbSmime.SelectedItem) {
        $smimeTp = ($ctl.CbSmime.SelectedItem.ToString() -split '\s+')[0]
    }

    $hibpFile = $ctl.TbHibpPath.Text.Trim()
    if ($ctl.RbHibpDownload.IsChecked) {
        $hibpFile = Join-Path $ctl.TbHibpDownloadDir.Text.Trim() 'pwnedpasswords.ntlm.txt'
    }

    return @{
        Domain                     = $ctl.TbDomain.Text.Trim()
        DomainController           = $ctl.TbDC.Text.Trim()
        AuditStation               = $ctl.TbStation.Text.Trim()
        SmbShareUnc                = $ctl.TbSmb.Text.Trim()
        WorkDirectory              = $ctl.TbWorkDir.Text.Trim()
        LogDirectory               = $ctl.TbLogDir.Text.Trim()
        ReportRetentionDirectory   = $ctl.TbReportDir.Text.Trim()
        AttestationDirectory       = $ctl.TbAttestDir.Text.Trim()
        HibpFilePath               = $hibpFile
        HibpExpectedSha256         = $ctl.TbHibpSha.Text.Trim()
        HibpDownload               = [bool]$ctl.RbHibpDownload.IsChecked
        HibpDownloadDir            = $ctl.TbHibpDownloadDir.Text.Trim()
        SecretVaultName            = 'ADAuditVault'
        IfmKeyName                 = 'ADAudit-IFM-Key'
        SmtpServer                 = $ctl.TbSmtp.Text.Trim()
        SmtpPort                   = [int]$ctl.TbSmtpPort.Text
        SmtpFrom                   = $ctl.TbSmtpFrom.Text.Trim()
        SmtpRecipients             = $rec
        SmimeCertificateThumbprint = $smimeTp
        ReportRetentionDays        = [int]$ctl.TbRetention.Text
        ScheduleDay                = [int]$ctl.TbDay.Text
        ScheduleHourDC             = [int]$ctl.TbHourDC.Text
        ScheduleHourStation        = [int]$ctl.TbHourStation.Text
        SvcUser                    = $ctl.TbSvcUser.Text.Trim()
    }
}

function Update-Review {
    $m = Get-WizardModel
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('=== Will be written to audit.config.psd1 ===')
    foreach ($k in 'Domain','DomainController','AuditStation','SmbShareUnc',
                   'WorkDirectory','LogDirectory','ReportRetentionDirectory','AttestationDirectory',
                   'HibpFilePath','HibpExpectedSha256','SecretVaultName','IfmKeyName',
                   'SmtpServer','SmtpPort','SmtpFrom','SmimeCertificateThumbprint','ReportRetentionDays') {
        [void]$sb.AppendFormat('  {0,-30} = {1}', $k, $m[$k]).AppendLine()
    }
    [void]$sb.AppendFormat('  {0,-30} = {1}', 'SmtpRecipients', ($m.SmtpRecipients -join ', ')).AppendLine()
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('=== Will be done: ===')
    [void]$sb.AppendLine('  - install 7-Zip, SDelete64, RSAT-AD-PowerShell')
    [void]$sb.AppendLine('  - install modules SecretManagement / SecretStore / DSInternals')
    [void]$sb.AppendLine('  - initialize vault, generate AES-256 IFM key')
    if ($m.HibpDownload) {
        [void]$sb.AppendLine('  - download HIBP NTLM (~30 GB) into ' + $m.HibpDownloadDir)
    } else {
        [void]$sb.AppendLine('  - verify existing HIBP via SHA-256')
    }
    [void]$sb.AppendLine('  - create directories with hardened ACL: ' + $m.WorkDirectory + ', ' + $m.LogDirectory + ', ' + $m.ReportRetentionDirectory)
    [void]$sb.AppendLine(('  - register Scheduled Tasks: Phase1 on DC ({0} day at {1}:00 UTC), Orchestrator on station ({0} day at {2}:00 UTC), Retention daily at 03:30.' -f $m.ScheduleDay, $m.ScheduleHourDC, $m.ScheduleHourStation))
    [void]$sb.AppendLine('  - assemble bootstrap zip for the DC (ADPasswordAudit-DC-bootstrap.zip).')
    $ctl.TbReview.Text = $sb.ToString()
}

# ============================================================
# Background runner
# ============================================================
function Start-BackgroundJob {
    param(
        [Parameter(Mandatory)] [scriptblock] $Script,
        [hashtable] $JobArgsTable = @{},
        [Parameter(Mandatory)] $LogTextBox,
        [Parameter(Mandatory)] $ProgressBar,
        [scriptblock] $OnDone = $null
    )
    if ($script:RunPS) {
        [System.Windows.MessageBox]::Show('A background job is already running. Wait or press Cancel.','Busy') | Out-Null
        return
    }
    $LogTextBox.Clear()
    $script:UiSync.Status   = 'running'
    $script:UiSync.Progress = 0
    $script:UiSync.Lines    = New-Object System.Collections.Concurrent.ConcurrentQueue[string]

    $script:RunSpace = [runspacefactory]::CreateRunspace()
    $script:RunSpace.ApartmentState = 'STA'
    $script:RunSpace.ThreadOptions  = 'ReuseThread'
    $script:RunSpace.Open()
    $script:RunSpace.SessionStateProxy.SetVariable('Sync',     $script:UiSync)
    $script:RunSpace.SessionStateProxy.SetVariable('JobArgs',  $JobArgsTable)
    $script:RunSpace.SessionStateProxy.SetVariable('RepoRoot', $script:RepoRoot)

    $script:RunPS = [powershell]::Create()
    $script:RunPS.Runspace = $script:RunSpace
    [void]$script:RunPS.AddScript($Script)
    $handle = $script:RunPS.BeginInvoke()

    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(120)
    $timer.Add_Tick({
        $line = $null
        while ($script:UiSync.Lines.TryDequeue([ref]$line)) {
            $LogTextBox.AppendText($line + [Environment]::NewLine)
            $LogTextBox.ScrollToEnd()
        }
        $ProgressBar.Value = [int]$script:UiSync.Progress
        if ($handle.IsCompleted) {
            $timer.Stop()
            try { $script:RunPS.EndInvoke($handle) | Out-Null } catch {
                $LogTextBox.AppendText('!! ' + $_.Exception.Message + [Environment]::NewLine)
            }
            $script:RunPS.Dispose();   $script:RunPS = $null
            $script:RunSpace.Close();  $script:RunSpace = $null
            $script:UiSync.Status = 'done'
            if ($OnDone) { & $OnDone }
        }
    })
    $timer.Start()
}

function Stop-BackgroundJob {
    if ($script:RunPS) {
        try { $script:RunPS.Stop() } catch {}
        $script:RunPS.Dispose(); $script:RunPS = $null
    }
    if ($script:RunSpace) {
        try { $script:RunSpace.Close() } catch {}
        $script:RunSpace = $null
    }
    $script:UiSync.Status = 'cancelled'
}

# ============================================================
# Install job (runs in a runspace; talks to UI via $Sync.Lines)
# ============================================================
$script:InstallJob = {
    function Log {
        param([string]$Msg, [string]$Level='INFO')
        $stamp = (Get-Date).ToUniversalTime().ToString('HH:mm:ss')
        $Sync.Lines.Enqueue("$stamp [$Level] $Msg")
    }
    function Step {
        param([int]$Pct,[string]$Msg)
        $Sync.Progress = $Pct
        Log $Msg 'STEP'
    }

    try {
        Step 2 'Checking internet access for component download...'
        try { Invoke-WebRequest -Uri 'https://github.com' -UseBasicParsing -TimeoutSec 10 | Out-Null }
        catch { Log "Internet unavailable: $($_.Exception.Message). Check proxy settings." 'WARN' }

        # 1. 7-Zip
        Step 6 '7-Zip: probe / install...'
        $sevenZipExe = $null
        $cmd = Get-Command 7z.exe -ErrorAction SilentlyContinue
        if ($cmd) { $sevenZipExe = $cmd.Source }
        if (-not $sevenZipExe) {
            $msi = Join-Path $env:TEMP '7z-install.msi'
            Invoke-WebRequest -Uri 'https://www.7-zip.org/a/7z2301-x64.msi' -OutFile $msi -UseBasicParsing
            Start-Process msiexec.exe -ArgumentList '/i', $msi, '/qn' -Wait
            $sevenZipExe = 'C:\Program Files\7-Zip\7z.exe'
        }
        Log "7-Zip: $sevenZipExe"

        # 2. SDelete
        Step 12 'SDelete64: probe / install...'
        $sd = 'C:\Tools\SDelete\sdelete64.exe'
        if (-not (Test-Path -LiteralPath $sd)) {
            New-Item -ItemType Directory -Path 'C:\Tools\SDelete' -Force | Out-Null
            $zip = Join-Path $env:TEMP 'sdelete.zip'
            Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/SDelete.zip' -OutFile $zip -UseBasicParsing
            Expand-Archive -LiteralPath $zip -DestinationPath 'C:\Tools\SDelete' -Force
            New-Item -Path 'HKCU:\Software\Sysinternals\SDelete' -Force | Out-Null
            New-ItemProperty -Path 'HKCU:\Software\Sysinternals\SDelete' -Name EulaAccepted -Value 1 -PropertyType DWord -Force | Out-Null
        }
        Log "SDelete: $sd"

        # 3. PS modules
        Step 18 'PowerShell modules: SecretManagement / SecretStore / DSInternals...'
        if (-not (Get-Module -ListAvailable -Name Microsoft.PowerShell.SecretManagement)) {
            Install-Module -Name Microsoft.PowerShell.SecretManagement -Scope AllUsers -Force -AcceptLicense
        }
        if (-not (Get-Module -ListAvailable -Name Microsoft.PowerShell.SecretStore)) {
            Install-Module -Name Microsoft.PowerShell.SecretStore -Scope AllUsers -Force -AcceptLicense
        }
        if (-not (Get-Module -ListAvailable -Name DSInternals)) {
            Install-Module -Name DSInternals -Scope AllUsers -Force -AcceptLicense
        }

        Step 26 'RSAT-AD-PowerShell...'
        try {
            $f = Get-WindowsFeature -Name RSAT-AD-PowerShell -ErrorAction SilentlyContinue
            if ($f -and -not $f.Installed) { Install-WindowsFeature -Name RSAT-AD-PowerShell | Out-Null }
        } catch { Log "RSAT-AD-PowerShell: $($_.Exception.Message)" 'WARN' }

        # 4. Vault + AES key
        Step 32 'Initialize SecretStore (Authentication=None) + AES-256...'
        Import-Module Microsoft.PowerShell.SecretStore -Force
        Import-Module Microsoft.PowerShell.SecretManagement -Force
        if (-not (Get-SecretVault -Name 'ADAuditVault' -ErrorAction SilentlyContinue)) {
            Register-SecretVault -Name 'ADAuditVault' -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
        }
        Set-SecretStoreConfiguration -Authentication None -Interaction None -Confirm:$false -ErrorAction SilentlyContinue
        Import-Module (Join-Path $RepoRoot 'Common\Crypto.psm1') -Force
        $aesKey = New-AesKey
        Save-AesKeyToSecretStore -Name 'ADAudit-IFM-Key' -Key $aesKey -VaultName 'ADAuditVault'
        Clear-SensitiveVariable -SecureString $aesKey

        # 5. Service credential
        Step 38 'Save service account credential into vault...'
        $svcSecure = ConvertTo-SecureString $JobArgs.SvcPasswordPlain -AsPlainText -Force
        Set-Secret -Name 'BackupOpCredential' -Vault 'ADAuditVault' -SecureStringSecret $svcSecure
        $JobArgs.SvcPasswordPlain = $null
        $svcSecure = $null
        [GC]::Collect()

        # 6. HIBP
        if ($JobArgs.Cfg.HibpDownload) {
            Step 42 'Fetch haveibeenpwned-downloader.exe...'
            $rel = Invoke-RestMethod 'https://api.github.com/repos/HaveIBeenPwned/PwnedPasswordsDownloader/releases/latest' -UseBasicParsing
            $asset = $null
            foreach ($a in $rel.assets) {
                if ($a.name -like 'haveibeenpwned-downloader*win-x64*.zip') { $asset = $a; break }
            }
            if (-not $asset) {
                foreach ($a in $rel.assets) { if ($a.name -like '*.zip') { $asset = $a; break } }
            }
            if (-not $asset) { throw 'haveibeenpwned-downloader binary not found on GitHub Releases.' }
            $zip = Join-Path $env:TEMP $asset.name
            Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zip -UseBasicParsing
            $hbpRoot = Join-Path $env:TEMP 'hbp'
            Expand-Archive -LiteralPath $zip -DestinationPath $hbpRoot -Force
            $hbp = (Get-ChildItem $hbpRoot -Filter 'haveibeenpwned-downloader.exe' -Recurse | Select-Object -First 1).FullName
            New-Item -ItemType Directory -Path $JobArgs.Cfg.HibpDownloadDir -Force | Out-Null
            Step 50 ("Downloading NTLM dictionary into {0} (this is ~30 GB)..." -f $JobArgs.Cfg.HibpDownloadDir)
            $outFile = Join-Path $JobArgs.Cfg.HibpDownloadDir 'pwnedpasswords.ntlm.txt'
            & $hbp -n -o $outFile
            $JobArgs.Cfg.HibpFilePath = $outFile
        }
        Step 70 ('Computing SHA-256 of HIBP dictionary: ' + $JobArgs.Cfg.HibpFilePath)
        $sha = Get-Sha256Hash -Path $JobArgs.Cfg.HibpFilePath
        $JobArgs.Cfg.HibpExpectedSha256 = $sha
        Log "HIBP SHA-256: $sha"

        # 7. Directories
        Step 78 'Create directories...'
        foreach ($d in $JobArgs.Cfg.WorkDirectory, $JobArgs.Cfg.LogDirectory,
                       $JobArgs.Cfg.ReportRetentionDirectory, $JobArgs.Cfg.AttestationDirectory) {
            if ($d -and -not (Test-Path -LiteralPath $d)) {
                New-Item -ItemType Directory -Path $d -Force | Out-Null
                Log "  + $d"
            }
        }

        # 8. Save config
        Step 84 'Write audit.config.psd1...'
        Import-Module (Join-Path $RepoRoot 'Common\Config.psm1') -Force
        $cfgDir = 'C:\ProgramData\ADPasswordAudit'
        if (-not (Test-Path $cfgDir)) { New-Item -ItemType Directory -Path $cfgDir -Force | Out-Null }
        $cfgPath = Join-Path $cfgDir 'audit.config.psd1'
        $cfgClean = @{}
        foreach ($k in 'Domain','DomainController','AuditStation','SmbShareUnc','WorkDirectory','LogDirectory',
                       'ReportRetentionDirectory','AttestationDirectory','HibpFilePath','HibpExpectedSha256',
                       'SecretVaultName','IfmKeyName','SmtpServer','SmtpPort','SmtpFrom','SmtpRecipients',
                       'SmimeCertificateThumbprint','ReportRetentionDays') {
            if ($JobArgs.Cfg.ContainsKey($k) -and $null -ne $JobArgs.Cfg[$k]) {
                $cfgClean[$k] = $JobArgs.Cfg[$k]
            }
        }
        Save-AuditConfig -Config $cfgClean -Path $cfgPath
        Log "  $cfgPath"

        # 9. Scheduled tasks
        Step 90 'Register Scheduled Tasks (Orchestrator + Retention)...'
        $orchScript    = Join-Path $RepoRoot 'Orchestrator\Start-PasswordAudit.ps1'
        $retentScript  = Join-Path $RepoRoot 'Retention\Invoke-ReportRetention.ps1'

        $orchAction   = New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument ('-NoProfile -ExecutionPolicy Bypass -File "{0}" -ConfigPath "{1}"' -f $orchScript, $cfgPath)
        $retentAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument ('-NoProfile -ExecutionPolicy Bypass -File "{0}" -ConfigPath "{1}"' -f $retentScript, $cfgPath)

        $monthDay   = '{0:D2}' -f [int]$JobArgs.Cfg.ScheduleDay
        $monthHourS = '{0:D2}' -f [int]$JobArgs.Cfg.ScheduleHourStation
        $orchTrigger = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2026-01-${monthDay}T${monthHourS}:00:00Z</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByMonth>
        <DaysOfMonth><Day>$([int]$monthDay)</Day></DaysOfMonth>
        <Months><January/><February/><March/><April/><May/><June/><July/><August/><September/><October/><November/><December/></Months>
      </ScheduleByMonth>
    </CalendarTrigger>
  </Triggers>
</Task>
"@

        $svcUserForTask = $JobArgs.Cfg.SvcUser
        $svcSecurePwd   = Get-Secret -Name BackupOpCredential -Vault ADAuditVault -AsPlainText:$false
        $svcPlainPwd    = [System.Net.NetworkCredential]::new('', $svcSecurePwd).Password

        Register-ScheduledTask -TaskName 'ADPasswordAudit-Orchestrator' `
            -Action $orchAction -RunLevel Highest `
            -User $svcUserForTask -Password $svcPlainPwd -Force | Out-Null

        $taskXml  = [xml](Export-ScheduledTask -TaskName 'ADPasswordAudit-Orchestrator')
        $newTrig  = [xml]$orchTrigger
        $importNs = $taskXml.Task.OwnerDocument.ImportNode($newTrig.Task.Triggers, $true)
        $oldTrig  = $taskXml.Task.SelectSingleNode("*[local-name()='Triggers']")
        if ($oldTrig) { $taskXml.Task.RemoveChild($oldTrig) | Out-Null }
        $taskXml.Task.PrependChild($importNs) | Out-Null

        Register-ScheduledTask -Xml $taskXml.OuterXml `
            -TaskName 'ADPasswordAudit-Orchestrator' `
            -User $svcUserForTask -Password $svcPlainPwd -Force | Out-Null
        Log '  + ADPasswordAudit-Orchestrator (monthly, runs as service account)'

        $retTrigger = New-ScheduledTaskTrigger -Daily -At '03:30am'
        Register-ScheduledTask -TaskName 'ADPasswordAudit-Retention' `
            -Action $retentAction -Trigger $retTrigger -RunLevel Highest `
            -User $svcUserForTask -Password $svcPlainPwd -Force | Out-Null
        Log '  + ADPasswordAudit-Retention (daily 03:30, runs as service account)'

        $svcPlainPwd  = $null
        $svcSecurePwd = $null
        [GC]::Collect()

        # 10. DC bootstrap zip
        Step 96 'Build DC bootstrap zip: ADPasswordAudit-DC-bootstrap.zip...'
        $bootDir = Join-Path $env:TEMP 'adp-dc-boot'
        if (Test-Path $bootDir) { Remove-Item $bootDir -Recurse -Force }
        New-Item -ItemType Directory -Path $bootDir | Out-Null
        Copy-Item -Path (Join-Path $RepoRoot '*') -Destination $bootDir -Recurse
        Copy-Item -Path $cfgPath -Destination (Join-Path $bootDir 'audit.config.psd1')
        $readme = @'
# DC bootstrap

Run on the DC under Domain Admin:

    cd <copied-package>
    .\Installer\Install-DCComponents.ps1 -ConfigPath .\audit.config.psd1

After the DC installer completes, transfer the AES IFM key from the
audit station via CMS:

    # On the audit station:
    .\Installer\Export-IfmKey.ps1 `
        -ConfigPath C:\ProgramData\ADPasswordAudit\audit.config.psd1 `
        -DCCertThumbprint <thumbprint-of-DC-cert>

The DC reads ifm-key.p7m at next Phase 1 tick and SDeletes it.

Make sure the service account configured by the wizard has Read+Modify
on the SMB share configured in audit.config.psd1.
'@
        Set-Content -LiteralPath (Join-Path $bootDir 'DC-INSTALL-README.md') -Value $readme -Encoding UTF8
        $zipOut = Join-Path $JobArgs.Cfg.ReportRetentionDirectory 'ADPasswordAudit-DC-bootstrap.zip'
        if (Test-Path $zipOut) { Remove-Item $zipOut -Force }
        Compress-Archive -Path (Join-Path $bootDir '*') -DestinationPath $zipOut
        Log "  $zipOut"

        Step 100 'Done.'
        Log '=== INSTALL COMPLETE ===' 'STEP'
    } catch {
        Log ('FATAL: ' + $_.Exception.Message) 'ERROR'
        Log $_.ScriptStackTrace 'ERROR'
    }
}

# ============================================================
# Audit / Phase5 / Retention background jobs
# ============================================================
$script:RunAuditJob = {
    $stamp = (Get-Date).ToUniversalTime().ToString('HH:mm:ss')
    $Sync.Lines.Enqueue("$stamp [STEP] Starting orchestrator...")
    $Sync.Progress = 5
    $orch = Join-Path $RepoRoot 'Orchestrator\Start-PasswordAudit.ps1'
    if (-not (Test-Path $orch)) {
        $Sync.Lines.Enqueue("ERROR: $orch not found")
        return
    }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $orch `
        -ConfigPath $JobArgs.ConfigPath -WaitForArchiveMinutes 0 2>&1 |
        ForEach-Object {
            $line = $_.ToString()
            $Sync.Lines.Enqueue($line)
            if ($line -match 'Phase(\d)') { $Sync.Progress = [int]$Matches[1] * 18 }
        }
    $Sync.Progress = 100
    $Sync.Lines.Enqueue("$stamp [STEP] DONE (exit $LASTEXITCODE)")
}

$script:RunPhase5Job = {
    $script = Join-Path $RepoRoot 'Phase5-Cleanup\Invoke-SecureCleanup.ps1'
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -ConfigPath $JobArgs.ConfigPath 2>&1 |
        ForEach-Object {
            $Sync.Lines.Enqueue($_.ToString())
            $Sync.Progress = ($Sync.Progress + 5) % 100
        }
    $Sync.Progress = 100
}

$script:RunRetentionJob = {
    $script = Join-Path $RepoRoot 'Retention\Invoke-ReportRetention.ps1'
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -ConfigPath $JobArgs.ConfigPath 2>&1 |
        ForEach-Object {
            $Sync.Lines.Enqueue($_.ToString())
            $Sync.Progress = ($Sync.Progress + 7) % 100
        }
    $Sync.Progress = 100
}

# ============================================================
# Health
# ============================================================
function Update-Health {
    $ctl.DgTasks.Items.Clear()
    foreach ($name in 'ADPasswordAudit-Orchestrator','ADPasswordAudit-Retention','ADPasswordAudit-Phase1') {
        try {
            $t = Get-ScheduledTask -TaskName $name -ErrorAction Stop
            $i = $t | Get-ScheduledTaskInfo
            $row = [pscustomobject]@{
                TaskName     = $name
                State        = $t.State
                LastRunTime  = $i.LastRunTime.ToUniversalTime().ToString('u')
                LastResult   = ('0x{0:X}' -f $i.LastTaskResult)
                NextRunTime  = $i.NextRunTime.ToUniversalTime().ToString('u')
            }
            $ctl.DgTasks.Items.Add($row) | Out-Null
        } catch {
            $row = [pscustomobject]@{
                TaskName     = $name
                State        = 'not registered'
                LastRunTime  = ''
                LastResult   = ''
                NextRunTime  = ''
            }
            $ctl.DgTasks.Items.Add($row) | Out-Null
        }
    }

    $logDir = 'C:\AuditLogs'
    if (Test-Path $logDir) {
        $latest = Get-ChildItem -LiteralPath $logDir -Filter 'audit-*.log' |
                  Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
        if ($latest) {
            $tail = Get-Content -LiteralPath $latest.FullName -Tail 60
            $ctl.TbHealthLog.Text = ($tail -join [Environment]::NewLine)
        } else {
            $ctl.TbHealthLog.Text = '(no log files yet)'
        }
    } else {
        $ctl.TbHealthLog.Text = '(C:\AuditLogs does not exist yet - it appears after first install)'
    }
}

# ============================================================
# Wire-up
# ============================================================
$ctl.TbStation.Text = $env:COMPUTERNAME

function Update-CertList {
    $ctl.CbSmime.Items.Clear()
    $certs = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
             Where-Object { $_.NotAfter -gt (Get-Date) }
    foreach ($c in $certs) {
        $label = "$($c.Thumbprint)  -  $($c.Subject)  (exp $($c.NotAfter.ToString('yyyy-MM-dd')))"
        $ctl.CbSmime.Items.Add($label) | Out-Null
    }
    if ($ctl.CbSmime.Items.Count -gt 0) { $ctl.CbSmime.SelectedIndex = 0 }
}
Update-CertList
$ctl.BtnRefreshCerts.Add_Click({ Update-CertList })

$ctl.RbHibpExisting.Add_Checked({
    $ctl.HibpExistingPanel.IsEnabled = $true
    $ctl.HibpDownloadPanel.IsEnabled = $false
})
$ctl.RbHibpDownload.Add_Checked({
    $ctl.HibpExistingPanel.IsEnabled = $false
    $ctl.HibpDownloadPanel.IsEnabled = $true
})

foreach ($btnName in 'BtnBrowseWork','BtnBrowseLog','BtnBrowseReport','BtnBrowseAttest','BtnBrowseHibp','BtnBrowseHibpDl') {
    $btn = $ctl[$btnName]
    if (-not $btn) { continue }
    $btn.Add_Click({
        param($s,$e)
        $tb = $ctl[$s.Tag]
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.SelectedPath = $tb.Text
        if ($dlg.ShowDialog() -eq 'OK') { $tb.Text = $dlg.SelectedPath }
    }.GetNewClosure())
}

$ctl.BtnBack.Add_Click({ Set-WizardPage ($script:WizardPage - 1) })
$ctl.BtnNext.Add_Click({
    if ($script:WizardPage -lt $script:WizardMax) {
        Set-WizardPage ($script:WizardPage + 1)
    } else {
        $ctl.MainTabs.SelectedItem = $ctl.TabControlPanel
        Update-Health
    }
})

$ctl.BtnRecheckPreflight.Add_Click({ Invoke-Preflight })

$ctl.BtnTestDC.Add_Click({
    $ctl.DcTestResult.Text = 'Testing...'
    $ctl.DcTestResult.Foreground = '#A6ADC8'
    $dc = $ctl.TbDC.Text.Trim()
    try {
        $ping = Test-Connection -ComputerName $dc -Count 2 -Quiet -ErrorAction Stop
        if (-not $ping) { throw 'ICMP failed (or blocked).' }
        $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dc/RootDSE")
        $null = $de.RefreshCache()
        $nc = $de.Properties['defaultNamingContext'][0]
        $ctl.DcTestResult.Text = "OK - DC reachable. defaultNamingContext = $nc"
        $ctl.DcTestResult.Foreground = 'LightGreen'
    } catch {
        $ctl.DcTestResult.Text = "FAIL - cannot reach DC: $($_.Exception.Message)"
        $ctl.DcTestResult.Foreground = '#F38BA8'
    }
})

$ctl.BtnTestSmb.Add_Click({
    $share = $ctl.TbSmb.Text.Trim()
    try {
        if (-not (Test-Path -LiteralPath $share -PathType Container)) {
            throw "Not visible / no access: $share"
        }
        $probe = Join-Path $share ("probe-{0}.tmp" -f [guid]::NewGuid().ToString('N').Substring(0,8))
        Set-Content -LiteralPath $probe -Value 'probe' -ErrorAction Stop
        Remove-Item -LiteralPath $probe -Force
        $ctl.DcTestResult.Text = "OK - SMB reachable, write succeeded: $share"
        $ctl.DcTestResult.Foreground = 'LightGreen'
    } catch {
        $ctl.DcTestResult.Text = "FAIL - SMB: $($_.Exception.Message)"
        $ctl.DcTestResult.Foreground = '#F38BA8'
    }
})

$ctl.BtnVerifyCred.Add_Click({
    $u  = $ctl.TbSvcUser.Text.Trim()
    $p  = $ctl.PbSvcPass.Password
    $dc = $ctl.TbDC.Text.Trim()
    if (-not $u -or -not $p) {
        $ctl.CredTestResult.Text = 'Enter username and password.'
        return
    }
    try {
        $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dc", $u, $p)
        $null = $de.NativeObject
        $ctl.CredTestResult.Text = 'OK - bind succeeded; credential is valid.'
        $ctl.CredTestResult.Foreground = 'LightGreen'
    } catch {
        $ctl.CredTestResult.Text = "FAIL - bind failed: $($_.Exception.Message)"
        $ctl.CredTestResult.Foreground = '#F38BA8'
    }
})

$ctl.BtnInstall.Add_Click({
    if (-not $ctl.PbSvcPass.Password) {
        [System.Windows.MessageBox]::Show('Go back to step 3 and enter the service account password.','Need password') | Out-Null
        return
    }
    $cfg = Get-WizardModel
    $jobArgs = @{
        Cfg              = $cfg
        SvcPasswordPlain = $ctl.PbSvcPass.Password
        ConfigPath       = 'C:\ProgramData\ADPasswordAudit\audit.config.psd1'
    }
    $ctl.BtnInstall.IsEnabled = $false
    Start-BackgroundJob -Script $script:InstallJob -JobArgsTable $jobArgs `
        -LogTextBox $ctl.TbInstallLog -ProgressBar $ctl.PbInstall `
        -OnDone {
            $ctl.BtnInstall.IsEnabled = $true
            if ($script:UiSync.Progress -eq 100) {
                [System.Windows.MessageBox]::Show('Install complete. See Health Check.','Done') | Out-Null
                $ctl.MainTabs.SelectedItem = $ctl.TabHealth
                Update-Health
            }
        }
})

$ctl.BtnRunAudit.Add_Click({
    if (-not (Test-Path $script:ConfigPath)) {
        [System.Windows.MessageBox]::Show('No config found. Run the Wizard first.','No config') | Out-Null
        return
    }
    $ctl.BtnRunAudit.IsEnabled   = $false
    $ctl.BtnCancelAudit.IsEnabled = $true
    Start-BackgroundJob -Script $script:RunAuditJob `
        -JobArgsTable @{ ConfigPath = $script:ConfigPath } `
        -LogTextBox $ctl.TbAuditLog -ProgressBar $ctl.PbAudit `
        -OnDone {
            $ctl.BtnRunAudit.IsEnabled    = $true
            $ctl.BtnCancelAudit.IsEnabled = $false
        }
})
$ctl.BtnRunPhase5.Add_Click({
    Start-BackgroundJob -Script $script:RunPhase5Job `
        -JobArgsTable @{ ConfigPath = $script:ConfigPath } `
        -LogTextBox $ctl.TbAuditLog -ProgressBar $ctl.PbAudit
})
$ctl.BtnRunRetent.Add_Click({
    Start-BackgroundJob -Script $script:RunRetentionJob `
        -JobArgsTable @{ ConfigPath = $script:ConfigPath } `
        -LogTextBox $ctl.TbAuditLog -ProgressBar $ctl.PbAudit
})
$ctl.BtnCancelAudit.Add_Click({ Stop-BackgroundJob })
$ctl.BtnOpenReportDir.Add_Click({
    try {
        Import-Module (Join-Path $script:RepoRoot 'Common\Config.psm1') -Force
        $env:AD_AUDIT_CONFIG = $script:ConfigPath
        $cfg = Get-AuditConfig
        Start-Process explorer.exe -ArgumentList $cfg.ReportRetentionDirectory
    } catch {
        [System.Windows.MessageBox]::Show($_.Exception.Message,'Error') | Out-Null
    }
})

$ctl.BtnRefreshHealth.Add_Click({ Update-Health })
$ctl.BtnOpenLogDir.Add_Click({ Start-Process explorer.exe -ArgumentList 'C:\AuditLogs' })
$ctl.BtnOpenAttest.Add_Click({ Start-Process explorer.exe -ArgumentList 'C:\AuditLogs\Attestations' })

# Open on Health if config already exists, otherwise start the Wizard.
if (Test-Path $script:ConfigPath) {
    $ctl.HeaderSubtitle.Text = '  - operations console (config: ' + $script:ConfigPath + ')'
    $ctl.MainTabs.SelectedItem = $ctl.TabHealth
    Update-Health
} else {
    Set-WizardPage 0
    Invoke-Preflight
}

[void]$window.ShowDialog()
