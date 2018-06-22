//alert('oldboy');
/*
name = '清睿教育欢迎你的加入，运维联系人 毛先生：186xxxxxxxx';
Foo();
Bar();
function Foo() {
	console.log(name);
}
function Bar() {
	var name = 'zhuqiyu';
	console.log(name);
	//return name;
}
*/
var array1 = [11,22,3,44,55]
var dict1 = {'name':'zhuqiyu','gender':'male'}
for(var item in array1){
	console.log(item);
	console.log(array1[item]);
}
for(var item in dict1){
	console.log(dict1[item]);
}