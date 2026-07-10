using System.Diagnostics;
using System.Drawing.Drawing2D;
using System.Security.Cryptography;

namespace DCE432;

public sealed class MainForm : Form
{
    private readonly TextBox _input = Field();
    private readonly TextBox _output = Field();
    private readonly TextBox _password = Field(true);
    private readonly TextBox _confirm = Field(true);
    private readonly TextBox _recovery = Field();
    private readonly ComboBox _performance = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 250 };
    private readonly RadioButton _portable = new() { Text = "Portable mode (recommended, works across devices)", Checked = true, AutoSize = true };
    private readonly RadioButton _bound = new() { Text = "Device-bound mode (save the recovery key)", AutoSize = true };
    private readonly Button _encrypt = ActionButton("Encrypt File", Color.FromArgb(49, 113, 255));
    private readonly Button _decrypt = ActionButton("Decrypt File", Color.FromArgb(28, 166, 126));
    private readonly ProgressBar _progress = new() { Style = ProgressBarStyle.Marquee, MarqueeAnimationSpeed = 25, Visible = false, Height = 8, Dock = DockStyle.Bottom };
    private readonly Label _status = new() { Text = "Ready. You can drag a file onto this window.", AutoSize = true, ForeColor = Color.FromArgb(130, 143, 164) };
    private readonly Label _passwordHint = new() { Text = "At least 8 characters. A long passphrase is recommended.", AutoSize = true, ForeColor = Color.FromArgb(130, 143, 164) };

    public MainForm()
    {
        Text = "DCE-432 Dynamic Cascade Encryption";
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(850, 700);
        Size = new Size(920, 780);
        BackColor = Color.FromArgb(15, 20, 31);
        ForeColor = Color.FromArgb(233, 238, 247);
        Font = new Font("Segoe UI", 10f);
        AllowDrop = true;
        DragEnter += (_, e) => { if (e.Data?.GetDataPresent(DataFormats.FileDrop) == true) e.Effect = DragDropEffects.Copy; };
        DragDrop += (_, e) => { if (e.Data?.GetData(DataFormats.FileDrop) is string[] files && files.Length > 0) SetInput(files[0]); };

        _performance.Items.AddRange([
            $"Auto-detect (this device: level {Dce432Engine.DetectPerformanceLevel()})",
            "Low (level 2 / 64 MB)", "Balanced (level 6 / 96 MB)",
            "High (level 10 / 128 MB)", "Maximum (level 14 / 256 MB)"]);
        _performance.SelectedIndex = 0;

        var root = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(34, 28, 34, 24), ColumnCount = 1, RowCount = 4 };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        Controls.Add(root);

        var title = new Label { Text = "DCE-432", Font = new Font("Segoe UI", 25f, FontStyle.Bold), AutoSize = true, ForeColor = Color.White };
        var subtitle = new Label { Text = "Dynamic Cascade Encryption - Authenticated File Container v0.1", AutoSize = true, ForeColor = Color.FromArgb(130, 151, 193), Margin = new Padding(2, 2, 0, 22) };
        var header = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false };
        header.Controls.Add(title); header.Controls.Add(subtitle); root.Controls.Add(header);

        var card = new Panel { Dock = DockStyle.Fill, BackColor = Color.FromArgb(24, 31, 47), Padding = new Padding(24), Margin = new Padding(0, 0, 0, 18), AutoScroll = true };
        var form = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 3, RowCount = 8 };
        form.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 112));
        form.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        form.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 104));
        card.Controls.Add(form); root.Controls.Add(card);

        AddFileRow(form, 0, "Input File", _input, "Browse...", BrowseInput);
        AddFileRow(form, 1, "Output File", _output, "Save As...", BrowseOutput);
        AddLabeled(form, 2, "Password", _password); form.Controls.Add(_passwordHint, 1, 3);
        AddLabeled(form, 4, "Confirm", _confirm);
        AddLabeled(form, 5, "Performance", _performance);
        var modes = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false };
        modes.Controls.Add(_portable); modes.Controls.Add(_bound); AddLabeled(form, 6, "Mode", modes);
        var recoveryPanel = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true };
        _recovery.Width = 430; _recovery.PlaceholderText = "Enter a recovery key for a device-bound file";
        var copy = SmallButton("Copy"); copy.Click += (_, _) => { if (_recovery.TextLength > 0) Clipboard.SetText(_recovery.Text); };
        recoveryPanel.Controls.Add(_recovery); recoveryPanel.Controls.Add(copy); AddLabeled(form, 7, "Recovery Key", recoveryPanel);

        var actions = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, FlowDirection = FlowDirection.LeftToRight, Margin = new Padding(0, 0, 0, 14) };
        _encrypt.Click += async (_, _) => await EncryptAsync();
        _decrypt.Click += async (_, _) => await DecryptAsync();
        actions.Controls.Add(_encrypt); actions.Controls.Add(_decrypt); root.Controls.Add(actions);

        var footer = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false };
        footer.Controls.Add(_status);
        footer.Controls.Add(new Label { Text = "Security boundary: Argon2id + AES-256-GCM. The high-dimensional cascade is an experimental reversible structure.", AutoSize = true, ForeColor = Color.FromArgb(104, 116, 138), Margin = new Padding(0, 7, 0, 0) });
        root.Controls.Add(footer);
        Controls.Add(_progress);

        _bound.CheckedChanged += (_, _) => _recovery.PlaceholderText = _bound.Checked ? "A recovery key will appear here after encryption" : "Enter a recovery key for a device-bound file";
        _input.TextChanged += (_, _) => { if (File.Exists(_input.Text) && string.IsNullOrWhiteSpace(_output.Text)) SuggestOutput(); };
    }

    private async Task EncryptAsync()
    {
        if (_password.Text != _confirm.Text) { ShowError("The passwords do not match."); return; }
        if (!File.Exists(_input.Text)) { ShowError("Select a valid input file."); return; }
        if (string.IsNullOrWhiteSpace(_output.Text)) SuggestOutput();
        try
        {
            SetBusy(true, "Preparing encryption...");
            var level = SelectedPerformanceLevel();
            var progress = new Progress<string>(s => _status.Text = s);
            var result = await Dce432Engine.EncryptFileAsync(_input.Text, _output.Text, _password.Text, new EncryptionOptions(level, _bound.Checked), progress);
            if (result.RecoveryKey is not null)
            {
                _recovery.Text = result.RecoveryKey;
                MessageBox.Show(this, "Device-bound encryption is complete. The recovery key is shown in the window. Copy it and store it separately from the encrypted file. If this device is lost and you do not have the recovery key, the file cannot be decrypted.", "Save Your Recovery Key", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            _status.Text = $"Complete: {FormatBytes(result.OriginalBytes)} -> {FormatBytes(result.EncryptedBytes)}. Performance level {result.PerformanceLevel}; {result.Rounds} 4D diffusion rounds.";
            MessageBox.Show(this, $"Encryption complete:\n{result.OutputPath}", "DCE-432", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex) { ShowError(ex.Message); }
        finally { SetBusy(false); }
    }

    private async Task DecryptAsync()
    {
        if (!File.Exists(_input.Text)) { ShowError("Select a valid DCE-432 file."); return; }
        try
        {
            var header = Dce432Engine.Inspect(_input.Text);
            if (string.IsNullOrWhiteSpace(_output.Text) || _output.Text.EndsWith(".dce432", StringComparison.OrdinalIgnoreCase))
                _output.Text = Path.Combine(Path.GetDirectoryName(_input.Text)!, Path.GetFileNameWithoutExtension(_input.Text) + (string.IsNullOrEmpty(header.FileType) ? ".decrypted" : header.FileType));
            SetBusy(true, "Preparing decryption...");
            var progress = new Progress<string>(s => _status.Text = s);
            var result = await Dce432Engine.DecryptFileAsync(_input.Text, _output.Text, _password.Text, _recovery.Text, progress);
            _status.Text = $"Decryption complete: {result.OriginalFileName}, {FormatBytes(result.OriginalBytes)}. Authentication and plaintext hash checks passed.";
            MessageBox.Show(this, $"Decryption complete:\n{result.OutputPath}", "DCE-432", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex) { ShowError(ex.Message); }
        finally { SetBusy(false); }
    }

    private void BrowseInput()
    {
        using var dialog = new OpenFileDialog { Title = "Select a File to Encrypt or Decrypt", Filter = "All files|*.*|DCE-432 files|*.dce432" };
        if (dialog.ShowDialog(this) == DialogResult.OK) SetInput(dialog.FileName);
    }
    private void BrowseOutput()
    {
        using var dialog = new SaveFileDialog { Title = "Choose an Output Location", FileName = Path.GetFileName(_output.Text), InitialDirectory = Path.GetDirectoryName(_output.Text) };
        if (dialog.ShowDialog(this) == DialogResult.OK) _output.Text = dialog.FileName;
    }
    private void SetInput(string path) { _input.Text = path; _output.Clear(); SuggestOutput(); }
    private void SuggestOutput()
    {
        if (!File.Exists(_input.Text)) return;
        _output.Text = _input.Text.EndsWith(".dce432", StringComparison.OrdinalIgnoreCase)
            ? Path.Combine(Path.GetDirectoryName(_input.Text)!, Path.GetFileNameWithoutExtension(_input.Text) + ".decrypted")
            : _input.Text + ".dce432";
    }
    private int SelectedPerformanceLevel() => _performance.SelectedIndex switch { 1 => 2, 2 => 6, 3 => 10, 4 => 14, _ => Dce432Engine.DetectPerformanceLevel() };
    private void SetBusy(bool busy, string? status = null) { _encrypt.Enabled = _decrypt.Enabled = !busy; _progress.Visible = busy; if (status is not null) _status.Text = status; UseWaitCursor = busy; }
    private void ShowError(string message) { _status.Text = "Operation failed: " + message; MessageBox.Show(this, message, "DCE-432", MessageBoxButtons.OK, MessageBoxIcon.Error); }

    private static TextBox Field(bool password = false) => new() { Dock = DockStyle.Fill, Height = 34, UseSystemPasswordChar = password, BorderStyle = BorderStyle.FixedSingle, BackColor = Color.FromArgb(15, 21, 33), ForeColor = Color.White, Margin = new Padding(0, 5, 8, 5) };
    private static Button ActionButton(string text, Color color) => new() { Text = text, Width = 150, Height = 46, FlatStyle = FlatStyle.Flat, BackColor = color, ForeColor = Color.White, Font = new Font("Segoe UI", 10f, FontStyle.Bold), Margin = new Padding(0, 0, 14, 0), Cursor = Cursors.Hand };
    private static Button SmallButton(string text) => new() { Text = text, Width = 72, Height = 32, FlatStyle = FlatStyle.Flat, BackColor = Color.FromArgb(39, 50, 72), ForeColor = Color.White };
    private static void AddFileRow(TableLayoutPanel panel, int row, string label, Control field, string buttonText, Action action)
    {
        AddLabeled(panel, row, label, field);
        var button = SmallButton(buttonText); button.Dock = DockStyle.Fill; button.Margin = new Padding(0, 5, 0, 5); button.Click += (_, _) => action(); panel.Controls.Add(button, 2, row);
    }
    private static void AddLabeled(TableLayoutPanel panel, int row, string label, Control field)
    {
        panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        panel.Controls.Add(new Label { Text = label, AutoSize = true, ForeColor = Color.FromArgb(183, 194, 214), Anchor = AnchorStyles.Left, Margin = new Padding(0, 12, 10, 8) }, 0, row);
        panel.Controls.Add(field, 1, row); panel.SetColumnSpan(field, 1);
    }
    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB"]; double value = bytes; var unit = 0;
        while (value >= 1024 && unit < units.Length - 1) { value /= 1024; unit++; }
        return $"{value:0.##} {units[unit]}";
    }
}
