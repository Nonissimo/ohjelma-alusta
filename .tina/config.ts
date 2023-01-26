import { defineConfig } from "tinacms";

// Your hosting provider likely exposes this as an environment variable
const branch = process.env.HEAD || process.env.VERCEL_GIT_COMMIT_REF || "main";
const client_id = process.env.TINA_CLIENT_ID || null;
const client_token = process.env.TINA_TOKEN || null;


export default defineConfig({
  branch,
  clientId: client_id, 
  token: client_token, 
  build: {
    outputFolder: "admin",
    publicFolder: "static",
  },
  media: {
    tina: {
      mediaRoot: "",
      publicFolder: "static",
    },
  },
  schema: {
    collections: [
      {
        name: "ohjelma",
        label: "Ohjelmat",
        path: "content/fi/docs",
        fields: [
          {
            type: "string",
            name: "title",
            label: "Otsikko",
            isTitle: true,
            required: true,
          },
          {
            type: "number",
            name: "year",
            label: "Vuosi",
          },
          {
            type: "string",
            name: "categories",
            label: "Ohjelman tyyppi",
            list: true,
            options: [{
              value: 'sektoriohjelma',
              label: 'Sektoriohjelma'
            }, {
              value: 'linjaus',
              label: 'Linjaus'
            }, {
              value: 'poliittinen_ohjelma',
              label: 'Poliittinen ohjelma'
            }, {
              value: 'periaateohjelma',
              label: 'Periaateohjelma'
            }, {
              value: 'kannanotto',
              label: 'Kannanotto'
            }]
          },
          {
            type: "string",
            name: "hyvaksyja",
            label: "Hyväksyjä",
            options: [{
              value: 'Puoluevaltuusto',
              label: 'Puoluevaltuusto'
            }, {
              value: 'Puoluehallitus',
              label: 'Puoluehallitus'
            }, {
              value: 'Puoluekokous',
              label: 'Puoluekokous'
            }, {
              value: 'Työryhmä',
              label: 'Työryhmä'
            }, {
              value: 'Eduskuntaryhmä',
              label: 'Eduskuntaryhmä'
            }]
          },
          {
            type: "string",
            name: "voimassa",
            label: "Voimassaolo",
            options: [{
              value: 'vihrea',
              label: 'Vihreä: voimassa'
            }, {
              value: 'keltainen',
              label: 'Keltainen: voimassa varauksin'
            }, {
              value: 'punainen',
              label: 'Punainen: rauennut'
            }]
          },
          {
            type: "string",
            name: "disclaimer",
            label: "Varauma merkittäväksi ohjelman oheen"
          },
          {
            type: "string",
            name: "tags",
            label: "Politiikkasektori",
            list: true,
            options: [{
              value: 'talous',
              label: 'Talouspolitiikka'
            }, {
              value: 'ympäristö',
              label: 'Ympäristöpolitiikka'
            }, {
              value: 'koulutus',
              label: 'Koulutuspolitiikka'
            }, {
              value: 'tiede',
              label: 'Tiedepolitiikka'
            }, {
              value: 'kulttuuri',
              label: 'Kulttuuripolitiikka'
            }, {
              value: 'alue',
              label: 'Aluepolitiikka'
            }, {
              value: 'maatalous',
              label: 'Maatalouspolitiikka'
            }]
          },
          {
            type: "rich-text",
            name: "body",
            label: "Teksti",
            isBody: true,
          },
        ],
      },
    ],
  },
});
