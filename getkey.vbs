Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")
Set colItems = objWMIService.ExecQuery("Select * from SoftwareLicensingProduct Where PartialProductKey <> NULL")

For Each objItem in colItems
    WScript.Echo "Product Key: " & objItem.PartialProductKey
Next