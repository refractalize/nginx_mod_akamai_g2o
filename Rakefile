require 'fileutils'
include FileUtils

$nginx_version = "1.0.5"
$nginx_dir = "nginx-#{$nginx_version}"

task :setup_nginx do
  rm_rf $nginx_dir

  sh("wget http://nginx.org/download/#{$nginx_dir}.tar.gz")

  sh("tar xzf #{$nginx_dir}.tar.gz")

  rm $nginx_dir + '.tar.gz'

  mod_dir = Dir.pwd

  cd $nginx_dir
  sh("./configure --prefix=#{Dir.pwd}/prefix --add-module=#{mod_dir} --with-cc-opt=-Wno-deprecated-declarations")
  sh("make install")

  sh("patch prefix/conf/nginx.conf ../nginx.conf.patch")

  mkdir_p "prefix/html/download"
  cp "../success_page.html", "prefix/html/download/stuff.html"
end

task :make_conf_patch do
  sh("diff -u #{$nginx_dir}/prefix/conf/nginx.conf.default #{$nginx_dir}/prefix/conf/nginx.conf > nginx.conf.patch")
end

task :run_nginx do
  sh("#{$nginx_dir}/prefix/sbin/nginx")
end
