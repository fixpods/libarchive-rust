#!/bin/bash
rm -rf failfile.txt
for file in ./*
do
if [ -d "$file" ]
then
  echo "testing bsdtar - $file"
  if(($? == 0));then
    echo "success"
  else
    echo "$file - bsdtar fail" >> ./failfile.txt
    echo "fail"
  fi
  echo "testing bsdcpio - $file"
  if(($? == 0));then
    echo "success"
  else
    echo "$file - bsdcpio fail" >> ./failfile.txt
    echo "fail"
  fi
fi
done