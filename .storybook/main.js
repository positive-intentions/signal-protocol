// const {
//   withStorybookModuleFederation,
// } = require('storybook-module-federation');
const { ModuleFederationPlugin } = require("webpack").container;
var deps = require('../package.json').dependencies;

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
      console.warn('Module federation remote not available:', error.message);
      return [];
    });
  
  const availableUrls = urlPings.filter(url => !!url);
  
  if (availableUrls.length === 0) {
    console.warn('No remote URLs available for', '${moduleName}');
    resolve({
      get: () => Promise.reject(new Error('Remote module not available')),
      init: () => {}
    });
    return;
  }
  
  const firstAvailableUrl = availableUrls
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

const moduleFederationConfig = new ModuleFederationPlugin({
  name: "signal_protocol",
  filename: "remoteEntry.js",
  exposes: {
    './SignalProtocol': './src/stories/components/SignalProtocolDemo.tsx',
    './WasmBindings': './src/wasm-bindings.js',
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
      singleton: false,
      requiredVersion: deps.react,
      eager: true
    },
    "react-dom": {
      singleton: false,
      requiredVersion: deps["react-dom"],
      eager: true
    }
  }
})

/** @type { import('@storybook/react-webpack5').StorybookConfig } */
const config = {
  stories: ["../src/**/*.mdx", "../src/**/*.stories.@(js|jsx|mjs|ts|tsx)"],

  webpackFinal: async (config) => {
    config.plugins.push(moduleFederationConfig);

    // Resolve emotion duplication
    config.resolve.alias = {
      ...config.resolve.alias,
      '@emotion/react': require.resolve('@emotion/react'),
      '@emotion/styled': require.resolve('@emotion/styled'),
    };

    // Add WASM file watching for hot reload
    if (config.watchOptions) {
      config.watchOptions.ignored = config.watchOptions.ignored || [];
      // Remove pkg directory from ignored so WASM files are watched
      if (Array.isArray(config.watchOptions.ignored)) {
        config.watchOptions.ignored = config.watchOptions.ignored.filter(
          pattern => !pattern.toString().includes('pkg')
        );
      }
    }

    // Ensure WASM files are treated as assets
    config.module.rules.push({
      test: /\.wasm$/,
      type: 'asset/resource',
    });

    return config;
  },

  addons: [
    "@storybook/addon-links",
    "@storybook/addon-docs",
    "@storybook/addon-webpack5-compiler-swc",
    "@storybook/addon-themes",
  ],

  framework: {
    name: "@storybook/react-webpack5",
    options: {
      builder: {},
    },
  },

  staticDirs: ['../public'],

  typescript: {
    reactDocgen: "react-docgen-typescript"
  },

  core: {
    disableWhatsNewNotifications: true,
  }
};

// export default withStorybookModuleFederation(moduleFederationConfig)(
//   config
// );

export default config;