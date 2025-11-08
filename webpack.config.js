const HtmlWebpackPlugin = require('html-webpack-plugin');
const { ModuleFederationPlugin } = require('webpack').container;
const WebpackPwaManifest = require('webpack-pwa-manifest');
const path = require('path');
var deps = require('./package.json').dependencies;

const moduleRedundency = ({
  moduleName,
  urls
}) => (`promise new Promise(async (resolve) => {

    function getRandomNumber(min, max) {
      if (min > max) {
          throw new Error("Minimum value must be less than or equal to the maximum value.");
      }
      // Generate and return a random integer between min and max, inclusive
      return Math.floor(Math.random() * (max - min + 1) + min);
    }
  
    const urls = ${JSON.stringify(urls)}
  
  
    function checkUrl(url) {
      const timestamp = Date.now();
      return fetch(url, {
        method: "HEAD",
        mode: 'no-cors'
      })
        .then(res => {
            return {
              url,
              ping: Date.now() - timestamp
            }
        })
        .catch(error => null);
    }
  
    const availabilityPromises = urls
      .map(url =>
        checkUrl(url)
      )
      .filter(url => !!url);
  
    // Use Promise.race to find the first URL that responds with an available resource
    const urlPings = await Promise.all(availabilityPromises)
      .catch(error => {
        // Handle the case where none of the URLs are available
        reject(new Error('None of the URLs responded positively: ' + error.message));
      });
    
    const firstAvailableUrl = urlPings
      .filter(url => !!url)
      .reduce((lowest, item) => {
          return item.ping < lowest.ping ? item : lowest;
      });
  
    const remoteUrlWithVersion = firstAvailableUrl.url;
    const script = document.createElement('script')
    script.src = remoteUrlWithVersion
    script.onload = () => {
      // the injected script has loaded and is available on window
      // we can now resolve this Promise
      const proxy = {
        get: (request) => window.${moduleName}.get(request),
        init: (arg) => {
          try {
            return window.${moduleName}.init(arg)
          } catch(e) {
            console.log('remote container already initialized')
          }
        }
      }
      resolve(proxy)
    }
    // inject this script with the src set to the versioned remoteEntry.js
    document.head.appendChild(script);
  })
  `);

module.exports = {
  mode: 'development',
  entry: './src/index.ts',
  output: {
    filename: 'index.js',
    path: __dirname + '/dist',
    publicPath: 'auto',
  },
  resolve: {
    extensions: ['.tsx', '.ts', '.js', '.jsx'],
    fallback: {
      "crypto": false, // Use browser's window.crypto instead of Node.js crypto
    },
    // Handle missing WASM module gracefully
    alias: {
      // Optional: Add alias if pkg directory doesn't exist
    },
  },
  // Ignore missing optional dependencies (like WASM)
  ignoreWarnings: [
    {
      module: /pkg\/signal_protocol_wasm/,
    },
  ],
  devServer: {
    static: [
      {
        directory: path.join(__dirname, 'dist'),
      },
      {
        directory: path.join(__dirname, 'pkg'),
        publicPath: '/pkg',
      },
    ],
    hot: true,
    liveReload: true,
    port: 8084,
    open: true,
    historyApiFallback: true,
    client: {
      overlay: false,
    },
    watchFiles: ['src/**/*'],
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
      'Access-Control-Allow-Headers': 'X-Requested-With, content-type, Authorization',
    },
  },
  module: {
    rules: [
      {
        test: /\.(js|ts|jsx|tsx)$/,
        loader: "babel-loader",
        exclude: /node_modules/,
        options: {
          presets: ["@babel/preset-react", "@babel/preset-typescript"],
        },
      },
      // css and scss loader
      {
        // test: /\.css$/,
        test: /\.(css|scss)$/,
        use: ["style-loader", "css-loader"],
      },

      // image loader
      {
        test: /\.(png|svg|jpg|jpeg|gif)$/i,
        type: "asset/resource",
      },
    ],
  },
  plugins: [
    new HtmlWebpackPlugin({
      template: './src/index.html',
    }),
    new WebpackPwaManifest({
      filename: "manifest.json",
      name: 'positive-intentions',
      short_name: 'PI',
      description: 'positive-intentions',
      "icons": [
        {
          src: path.resolve('./public/favicon.ico'),
          sizes: [96] // multiple sizes
        },
        {
          src: path.resolve('./public/logo512.png'),
          sizes: [96, 128, 192, 256, 384, 512], // multiple sizes
          maskable: true,
        }


      ],
      "start_url": ".",
      "display": "standalone",
      "theme_color": "#44b700",
      "background_color": "#ffffff",
      // crossorigin: 'use-credentials', // can be null, use-credentials or anonymous
      inject: true,
    }),
    new ModuleFederationPlugin({
      name: 'signal_protocol',
      filename: 'remoteEntry.js',
      exposes: {
        './SignalProtocol': './src/stories/components/SignalProtocolDemo.tsx',
        './WasmBindings': './src/wasm-bindings.js',
        // './Cryptography': './src/stories/components/Cryptography.tsx',
        // './mlsCodec': './src/crypto/MLS/mlsCodec.ts',
        // './CascadingCipher': './src/crypto/CascadingCipher/index.ts',
        // './pkg/signal_protocol_wasm': './pkg/signal_protocol_wasm.js',
      },
      remotes: {
        "dim": moduleRedundency({
          moduleName: 'dim',
          urls: [
            'http://localhost:8082/remoteEntry.js', // local for testing
            'https://positive-intentions.github.io/dim/remoteEntry.js',
            'https://dim.positive-intentions.com/remoteEntry.js'
          ]
        }),
        "ui": moduleRedundency({
          moduleName: 'ui',
          urls: [
            'http://localhost:8081/remoteEntry.js', // local for testing
            'https://positive-intentions.github.io/ui/remoteEntry.js',
            'https://ui.positive-intentions.com/remoteEntry.js'
          ]
        }),
        "cryptography": moduleRedundency({
          moduleName: 'cryptography',
          urls: [
            'http://localhost:8083/remoteEntry.js', // local for testing
            'https://positive-intentions.github.io/cryptography/remoteEntry.js',
            'https://cryptography.positive-intentions.com/remoteEntry.js'
          ]
        }),
      },
      shared: {
        react: {
          singleton: true,
          requiredVersion: deps.react,
          eager: true
        },
        "react-dom": {
          singleton: true,
          requiredVersion: deps["react-dom"],
          eager: true
        }
      }
    }),
  ],
};