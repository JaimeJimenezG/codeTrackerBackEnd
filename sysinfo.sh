#!/bin/sh
(
/bin/ps amcwwwxo "command %mem %cpu" | 
/usr/bin/awk -F" " '
BEGIN { 
  idx=0 
  format="%-20s /%-8s/ %-8s\n"
}
{
  idx = idx + 1
  col1=$0
  col2=$(NF-1)
  col3=$NF
  sub(/[[:space:]]+[^ ]+[[:space:]]+[^ ]+[[:space:]]*$/,"", col1)
  a[idx]=col1
  b[col1]+=col2
  c[col1]+=col3
}
END {
  for(i=2; i<=idx; i++) 
  {
    if (a[i] in b)
    {
      printf format, a[i], b[a[i]], c[a[i]]
      delete b[a[i]]
    }
  }
}
' > ../data/top.txt | 
/usr/bin/sort -rn -t '/' -k 2,2 | /usr/bin/tr -d '/' | /usr/bin/head -n 15
)