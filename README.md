# Burp Scope Monitor Extension
A Burp Suite Extension to monitor and keep track of tested endpoints.

![](http://g.recordit.co/MwAyLS1VkZ.gif)

## Main Features

- Simple, easy way to monitor new endpoints never tested
 - "New only" will show up only endpoints not analyzed yet
- Accessible from Proxy tab (right click, mark request as analyzed/not)
- Send to Repeater convenience
- Enforcment of Burp's in scope rules 
- Import/Export state file directly to a CSV file for convenience
- Autosave option

## Installation

1. Make sure you have Jython configured under Extender -> Options -> Python Environment. For further instructions, check PortSwigger official instructions at their [support page](https://support.portswigger.net/customer/portal/articles/1965930-how-to-install-an-extension-in-burp-suite).
2. `git clone git@github.com:Regala/burp-scope-monitor.git`
3. Import [main.py](main.py) in Extender - Extender -> Extensions -> Add -> Select Python -> Select [main.py](main.py)

## Documentation

Most of the options available in General or Import tabs are auto-explanatory. 

- *"Repeater request automatically marks as analyzed"* - when issuing a request to an endpoint from repeater, it marks this request as analyzed automatically.
- *"Color request in Proxy tab"* - this essentially applies the behavior of the extension in the Proxy tab, if you combine these options with "Show only highlighted items" in Proxy. However, it's not as pleasant to the eyes as the color pallete is limited. 
- *"Autosave periodically"* - backups the state file every 10 minutes. When activating this option, consider disabling *"Autostart Scope Monitor"*. This is in order to maintain a different state file per Burp project. However, you can easily maintain only one, master state file.

## Future Development

- Keep track of parameters observed in all requests
- Highlight when a new parameter was used in an already observed/analyzed endpoint
- Export to spreadsheet / Google Sheets
- Adding notes to the endpoint

## Contributing

I welcome contributions from the public, from bug reports, feature suggestions and pull requests.

### Using the issue tracker 💡

The issue tracker is the preferred channel for bug reports and features requests.

### Issues and labels 🏷

The bug tracker utilizes several labels to help organize and identify issues.

### Guidelines for bug reports 🐛

Use the GitHub issue search — check if the issue has already been reported.

## Special Thanks

- BlazeIt team
- BBAC
- HackerOne
