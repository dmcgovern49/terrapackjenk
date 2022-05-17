

set-location -path "C:\Windows\System32\GroupPolicy"

aws s3 sync s3://gpo-stuff-001 .

secedit /configure /cfg ./Security.csv /db defltbase.sdb /verbose

Auditpol /restore /file:C:\Windows\System32\GroupPolicy\audit.ini