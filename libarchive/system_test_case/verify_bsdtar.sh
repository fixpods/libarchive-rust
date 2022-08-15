#!/bin/bash
dir=$1
echo "正在使用 bsdtar 检查 $dir 文件夹"
mkdir ./tmp
find $dir -type f|xargs md5sum | awk '{ print $1 }' > ./tmp/data1.txt
bsdtar -cf archive $dir
cp -r archive ./tmp/
rm -rf archive
cd ./tmp/
bsdtar -xf archive
find $dir -type f|xargs md5sum | awk '{ print $1 }'> ./data2.txt
rm -rf archive $dir
cd ..
md5_1=` md5sum ./tmp/data1.txt | awk '{ print $1 }'`
md5_2=` md5sum ./tmp/data2.txt | awk '{ print $1 }'`
rm -rf ./tmp/
if [ $md5_1 != $md5_2 ]
then
echo "$i changed."
exit 1
else
echo "$i success."
exit 0
fi