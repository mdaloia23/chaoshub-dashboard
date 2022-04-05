import { Config } from 'poi'

const config: Config = {
  entry: 'src/index.ts',
  publicFolder: './public',
  output: [
    {
      sourceMap: false,
      html: {
        template: 'index.html',
      }
    },
  ],
  css: [
    {
      extract: true,
    },
  ],
  plugins: [
    {
      resolve: '@poi/plugin-typescript',
      options: {
        babel: true,
      },
    },
  ],
}

if (process.env.NODE_ENV === 'production') {
  /*
  options.filename = {
    js: 'static/js/[name].[chunkhash:8].js',
    css: 'static/css/[name].[chunkhash:8].css',
    image: 'static/img/[name].[ext]',
    font: 'static/fonts/[name].[ext]',
    chunk: 'static/js/[id].chunk.js'
  */
  }
}

export default config
