using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Task4
{
    public partial class Form1 : Form
    {
        [DllImport("DLL.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "signPdf")]
        public static extern bool signPdf(  string chrprivateKeyPath,   string chrpdfPath,   string chrsignaturePath);
        [DllImport("DLL.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "verifySignature")]
        public static extern bool verifySignature(  string chrprivateKeyPath,   string chrpdfPath,   string chrsignaturePath);
        public Form1()
        {
            InitializeComponent();
        }
        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private void button1_Click(object sender, EventArgs e)
        {
            try
            {
                if (comboBox1.SelectedItem.ToString() == "sign")
                {
                    if (!signPdf(textBox2.Text, textBox3.Text, textBox4.Text))
                    {
                        MessageBox.Show("PDF signed successfully");
                    }
                    else
                    {
                        MessageBox.Show("PDF signed failed");
                    }
                }
                if (comboBox1.SelectedItem.ToString() == "verify")
                {
                    if (!verifySignature(textBox2.Text, textBox3.Text, textBox4.Text))
                    {
                        MessageBox.Show("PDF verify successfully");
                    }
                    else
                    {
                        MessageBox.Show("PDF verify failed");
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("An error occurred: " + ex.Message);
            }

        }
    }
}
