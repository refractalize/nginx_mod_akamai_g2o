require 'fileutils'
include FileUtils

$nginx_version = "1.3.13"
$nginx_dir = "nginx-#{$nginx_version}"

desc 'build, patch and install nginx in this directory'
task :setup_nginx do
  rm_rf $nginx_dir

  sh("curl http://nginx.org/download/#{$nginx_dir}.tar.gz > #{$nginx_dir}.tar.gz")

  sh("tar xzf #{$nginx_dir}.tar.gz")

  rm $nginx_dir + '.tar.gz'

  mod_dir = Dir.pwd

  cd $nginx_dir
  sh("./configure --prefix=#{Dir.pwd}/prefix --add-module=#{mod_dir} --with-cc-opt=-Wno-deprecated-declarations")
  sh("make install")

  sh("patch prefix/conf/nginx.conf ../setup-files/nginx.conf.patch")

  make_content_dir 'download'
  make_content_dir 'allow_token1'
  make_content_dir 'allow_all'
end

def make_content_dir(dir)
  mkdir_p "prefix/html/#{dir}"
  cp "../setup-files/success_page.html", "prefix/html/#{dir}/stuff.html"
end

desc 'make the configuration patch containing changes for the ngo module'
task :make_conf_patch do
  system("diff -u #{$nginx_dir}/prefix/conf/nginx.conf.default #{$nginx_dir}/prefix/conf/nginx.conf", :out => "setup-files/nginx.conf.patch")
end

desc 'run nginx'
task :run_nginx do
  sh("#{$nginx_dir}/prefix/sbin/nginx")
end
