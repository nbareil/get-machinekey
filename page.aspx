<%@ Page Language="C#" AutoEventWireup="true"
    EnableViewStateMac="true"
    EnableEventValidation="false"
    EnableViewState="true" %>
<!DOCTYPE html>
<html>
<head runat="server">
    <title>ViewState MAC E2E Test</title>
</head>
<body>
    <form id="form1" runat="server">
        <div>
            <asp:Label ID="lblStatus" runat="server" />
            <br />
            <asp:Button ID="btnPostBack" runat="server" Text="Test Postback"
                OnClick="btnPostBack_Click" />
        </div>
    </form>
</body>
</html>

<script runat="server">
    protected void btnPostBack_Click(object sender, EventArgs e)
    {
        lblStatus.Text = "VIEWSTATE_E2E_OK";
    }
</script>

