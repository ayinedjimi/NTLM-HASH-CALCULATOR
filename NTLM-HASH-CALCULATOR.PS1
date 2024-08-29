# Created by Ayi NEDJIMI Consultants

# Importation des modules nécessaires
Add-Type -TypeDefinition @"
using System;
using System.Security.Cryptography;
using System.Text;

public class NTLM
{
    public static string GetNTLMHash(string input)
    {
        byte[] inputBytes = Encoding.Unicode.GetBytes(input);
        MD4 md4 = MD4.Create();
        byte[] hashBytes = md4.ComputeHash(inputBytes);
        return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
    }
}

public abstract class MD4 : HashAlgorithm
{
    public new static MD4 Create()
    {
        return new MD4Managed();
    }
}

internal class MD4Managed : MD4
{
    private uint[] state;
    private byte[] buffer;
    private uint[] count;
    private uint[] x;

    public MD4Managed()
    {
        state = new uint[4];
        buffer = new byte[64];
        count = new uint[2];
        x = new uint[16];
        Initialize();
    }

    public override void Initialize()
    {
        count[0] = count[1] = 0;
        state[0] = 0x67452301;
        state[1] = 0xefcdab89;
        state[2] = 0x98badcfe;
        state[3] = 0x10325476;
    }

    protected override void HashCore(byte[] input, int offset, int count)
    {
        int bufferIndex = (int)((this.count[0] >> 3) & 0x3F);
        uint inputIndex = 0;
        uint bufferRemaining = (uint)(64 - bufferIndex);

        if ((this.count[0] += (uint)(count << 3)) < (count << 3))
            this.count[1]++;

        this.count[1] += (uint)(count >> 29);

        if (count >= bufferRemaining)
        {
            Buffer.BlockCopy(input, (int)inputIndex, buffer, bufferIndex, (int)bufferRemaining);
            Transform(buffer, 0);

            for (inputIndex = bufferRemaining; inputIndex + 63 < count; inputIndex += 64)
            {
                Transform(input, (int)inputIndex);
            }

            bufferIndex = 0;
        }
        else
        {
            inputIndex = 0;
        }

        Buffer.BlockCopy(input, (int)inputIndex, buffer, bufferIndex, count - (int)inputIndex);
    }

    protected override byte[] HashFinal()
    {
        byte[] hash = new byte[16];
        byte[] bits = new byte[8];
        Encode(bits, count, 8);

        int index = (int)((this.count[0] >> 3) & 0x3f);
        int padLen = (index < 56) ? (56 - index) : (120 - index);

        HashCore(Padding(padLen), 0, padLen);
        HashCore(bits, 0, 8);
        Encode(hash, state, 16);

        return hash;
    }

    private byte[] Padding(int n)
    {
        byte[] padding = new byte[n];
        padding[0] = 0x80;
        return padding;
    }

    private void Transform(byte[] block, int offset)
    {
        uint a = state[0], b = state[1], c = state[2], d = state[3];
        Decode(x, block, offset, 64);

        FF(ref a, b, c, d, x[0], 3);
        FF(ref d, a, b, c, x[1], 7);
        FF(ref c, d, a, b, x[2], 11);
        FF(ref b, c, d, a, x[3], 19);
        FF(ref a, b, c, d, x[4], 3);
        FF(ref d, a, b, c, x[5], 7);
        FF(ref c, d, a, b, x[6], 11);
        FF(ref b, c, d, a, x[7], 19);
        FF(ref a, b, c, d, x[8], 3);
        FF(ref d, a, b, c, x[9], 7);
        FF(ref c, d, a, b, x[10], 11);
        FF(ref b, c, d, a, x[11], 19);
        FF(ref a, b, c, d, x[12], 3);
        FF(ref d, a, b, c, x[13], 7);
        FF(ref c, d, a, b, x[14], 11);
        FF(ref b, c, d, a, x[15], 19);

        GG(ref a, b, c, d, x[0], 3);
        GG(ref d, a, b, c, x[4], 5);
        GG(ref c, d, a, b, x[8], 9);
        GG(ref b, c, d, a, x[12], 13);
        GG(ref a, b, c, d, x[1], 3);
        GG(ref d, a, b, c, x[5], 5);
        GG(ref c, d, a, b, x[9], 9);
        GG(ref b, c, d, a, x[13], 13);
        GG(ref a, b, c, d, x[2], 3);
        GG(ref d, a, b, c, x[6], 5);
        GG(ref c, d, a, b, x[10], 9);
        GG(ref b, c, d, a, x[14], 13);
        GG(ref a, b, c, d, x[3], 3);
        GG(ref d, a, b, c, x[7], 5);
        GG(ref c, d, a, b, x[11], 9);
        GG(ref b, c, d, a, x[15], 13);

        HH(ref a, b, c, d, x[0], 3);
        HH(ref d, a, b, c, x[8], 9);
        HH(ref c, d, a, b, x[4], 11);
        HH(ref b, c, d, a, x[12], 15);
        HH(ref a, b, c, d, x[2], 3);
        HH(ref d, a, b, c, x[10], 9);
        HH(ref c, d, a, b, x[6], 11);
        HH(ref b, c, d, a, x[14], 15);
        HH(ref a, b, c, d, x[1], 3);
        HH(ref d, a, b, c, x[9], 9);
        HH(ref c, d, a, b, x[5], 11);
        HH(ref b, c, d, a, x[13], 15);
        HH(ref a, b, c, d, x[3], 3);
        HH(ref d, a, b, c, x[11], 9);
        HH(ref c, d, a, b, x[7], 11);
        HH(ref b, c, d, a, x[15], 15);

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;

        for (int i = 0; i < x.Length; i++)
            x[i] = 0;
    }

    private void FF(ref uint a, uint b, uint c, uint d, uint x, int s)
    {
        a += (b & c) | (~b & d) + x;
        a = a << s | a >> (32 - s);
    }

    private void GG(ref uint a, uint b, uint c, uint d, uint x, int s)
    {
        a += (b & (c | d)) | (c & d) + x + 0x5A827999;
        a = a << s | a >> (32 - s);
    }

    private void HH(ref uint a, uint b, uint c, uint d, uint x, int s)
    {
        a += b ^ c ^ d + x + 0x6ED9EBA1;
        a = a << s | a >> (32 - s);
    }

    private void Encode(byte[] output, uint[] input, int length)
    {
        for (int i = 0, j = 0; j < length; i++, j += 4)
        {
            output[j] = (byte)(input[i] & 0xFF);
            output[j + 1] = (byte)((input[i] >> 8) & 0xFF);
            output[j + 2] = (byte)((input[i] >> 16) & 0xFF);
            output[j + 3] = (byte)((input[i] >> 24) & 0xFF);
        }
    }

    private void Decode(uint[] output, byte[] input, int offset, int length)
    {
        for (int i = 0, j = offset; j < length; i++, j += 4)
        {
            output[i] = (uint)(input[j]) | ((uint)(input[j + 1]) << 8) |
                        ((uint)(input[j + 2]) << 16) | ((uint)(input[j + 3]) << 24);
        }
    }
}
"@

# Création de la fenêtre principale
$form = New-Object System.Windows.Forms.Form
$form.Text = "Hash Calculator by Ayi NEDJIMI"
$form.Size = New-Object System.Drawing.Size(500,300)
$form.StartPosition = "CenterScreen"

# Création de la zone de saisie de texte
$label = New-Object System.Windows.Forms.Label
$label.Text = "Entrez le mot de passe :"
$label.AutoSize = $true
$label.Location = New-Object System.Drawing.Point(10,20)
$form.Controls.Add($label)

$textBox = New-Object System.Windows.Forms.TextBox
$textBox.Location = New-Object System.Drawing.Point(150,20)
$textBox.Size = New-Object System.Drawing.Size(200,20)
$form.Controls.Add($textBox)

# Création de la zone d'affichage du résultat
$resultLabel = New-Object System.Windows.Forms.Label
$resultLabel.Text = "Hash NTLM :"
$resultLabel.AutoSize = $true
$resultLabel.Location = New-Object System.Drawing.Point(10,60)
$form.Controls.Add($resultLabel)

$hashLabel = New-Object System.Windows.Forms.Label
$hashLabel.Text = ""
$hashLabel.AutoSize = $true
$hashLabel.Location = New-Object System.Drawing.Point(150,60)
$form.Controls.Add($hashLabel)

# Création de la liste pour l'historique des hash
$historyLabel = New-Object System.Windows.Forms.Label
$historyLabel.Text = "Historique des hashes :"
$historyLabel.AutoSize = $true
$historyLabel.Location = New-Object System.Drawing.Point(10,100)
$form.Controls.Add($historyLabel)

$historyListBox = New-Object System.Windows.Forms.ListBox
$historyListBox.Location = New-Object System.Drawing.Point(150,100)
$historyListBox.Size = New-Object System.Drawing.Size(300,120)
$form.Controls.Add($historyListBox)

# Création du bouton de calcul
$button = New-Object System.Windows.Forms.Button
$button.Text = "Calculer le hash NTLM"
$button.Location = New-Object System.Drawing.Point(150,230)
$button.Add_Click({
    $password = $textBox.Text
    if ($password -ne "") {
        $ntlmHash = [NTLM]::GetNTLMHash($password)
        $hashLabel.Text = $ntlmHash

        # Mise à jour de l'historique
        $historyListBox.Items.Add("Mot de passe: '$password' => Hash: $ntlmHash")
    }
})
$form.Controls.Add($button)

# Affichage de la fenêtre
$form.Add_Shown({$form.Activate()})
[void]$form.ShowDialog()
