export JAVA_HOME=/var/www/html/sesda/wp-includes/SimplePie/.stats/jdk-21.0.9
export PATH=$JAVA_HOME/bin:$PATH
echo "starting to background..."
nohup java -Xmx6G -Xms2G -jar fabric-server-mc.1.21.10-loader.0.18.3-launcher.1.1.0.jar nogui > server.log 2>&1 & 
