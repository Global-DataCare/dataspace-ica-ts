import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

function signAndHashFile(targetPath, signKeyPath, runOpenSsl) {
  const content = readFileSync(targetPath);
  const digestHex = createHash('sha256').update(content).digest('hex');
  const shaFile = `${targetPath}.sha256`;
  const sigFile = `${targetPath}.sig`;
  writeFileSync(shaFile, `${digestHex}  ${path.basename(targetPath)}\n`);
  if (signKeyPath) {
    runOpenSsl(['dgst', '-sha256', '-sign', signKeyPath, '-out', sigFile, targetPath]);
  }
}

export function cmdDcatAddService(args, deps) {
  const {
    ensureDir,
    requireArg,
    runOpenSsl,
    writeJson,
  } = deps;
  const icaPublicRepo = path.resolve(requireArg(args, 'ica-public-repo'));
  const endpointUrl = requireArg(args, 'endpoint-url');
  const publisherDid = requireArg(args, 'publisher-did');
  const serviceTitle = args['service-title'] || 'Data Service';
  const serviceDescription = args['service-description'] || 'Data service published by ICA';
  const serviceDid = args['service-did'] || `did:web:${new URL(endpointUrl).host}`;
  const signKey = args['sign-key'] ? path.resolve(args['sign-key']) : null;

  const serviceHost = new URL(endpointUrl).host;
  const fileName = `dcat3_animal-index_${serviceHost}.jsonld`;
  const dcatDir = path.join(icaPublicRepo, 'dsp', 'dcat3', 'animal-index');
  ensureDir(dcatDir);
  const targetPath = path.join(dcatDir, fileName);

  const serviceDoc = {
    '@context': [
      'https://w3id.org/dspace/2025/1/context.jsonld',
      {
        dcat: 'http://www.w3.org/ns/dcat#',
        dct: 'http://purl.org/dc/terms/',
        sec: 'https://w3id.org/security#',
      },
    ],
    '@id': serviceDid,
    '@type': 'dcat:DataService',
    'dct:title': serviceTitle,
    'dct:description': serviceDescription,
    'dct:publisher': publisherDid,
    'dcat:endpointURL': endpointUrl,
    'sec:signature': {
      type: 'DetachedSignature',
      algorithm: 'SHA-256',
      signatureFile: `${fileName}.sig`,
    },
  };

  writeJson(targetPath, serviceDoc);
  signAndHashFile(targetPath, signKey, runOpenSsl);
  console.log(`DCAT service generated: ${targetPath}`);
}

export function cmdDcatBuildCatalog(args, deps) {
  const {
    ensureDir,
    requireArg,
    runOpenSsl,
    writeJson,
  } = deps;
  const icaPublicRepo = path.resolve(requireArg(args, 'ica-public-repo'));
  const publisherDid = requireArg(args, 'publisher-did');
  const baseUrl = requireArg(args, 'base-url').replace(/\/+$/, '');
  const catalogId = args['catalog-id'] || `${baseUrl}/dsp/dcat3/catalog`;
  const title = args.title || 'ICA Catalog';
  const description = args.description || 'Catalog of ICA services';
  const signKey = args['sign-key'] ? path.resolve(args['sign-key']) : null;

  const animalDir = path.join(icaPublicRepo, 'dsp', 'dcat3', 'animal-index');
  ensureDir(animalDir);
  const serviceFiles = readdirSync(animalDir).filter((fileName) => fileName.endsWith('.jsonld'));
  const serviceRefs = serviceFiles.map((fileName) => ({
    '@id': `${baseUrl}/dsp/dcat3/animal-index/${fileName}`,
  }));

  const catalog = {
    '@context': [
      'https://w3id.org/dspace/2025/1/context.jsonld',
      {
        dcat: 'http://www.w3.org/ns/dcat#',
        dct: 'http://purl.org/dc/terms/',
      },
    ],
    '@id': catalogId,
    '@type': 'dcat:Catalog',
    'dct:title': title,
    'dct:description': description,
    'dct:publisher': {
      '@id': publisherDid,
    },
    'dcat:service': serviceRefs,
  };

  const catalogPath = path.join(icaPublicRepo, 'dsp', 'dcat3', 'catalog.jsonld');
  writeJson(catalogPath, catalog);
  signAndHashFile(catalogPath, signKey, runOpenSsl);
  console.log(`DCAT catalog generated: ${catalogPath}`);
}
