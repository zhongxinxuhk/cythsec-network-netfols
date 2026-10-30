import type { Request, Response } from 'express';


import mapGeoData from './mock/map-geo';
import mapGridData from './mock/map-grid';

const getTags = (_: Request, res: Response) => {
  return res.json({
    data: { list: Array.from({ length: 100 }, (_, i) => ({ name: `城市 ${i + 1}`, value: 1 + ((i * 17) % 100), type: i % 3 })) },
  });
};

const getMapGeo = (_: Request, res: Response) => {
  return res.json(mapGeoData);
};

const getMapGrid = (_: Request, res: Response) => {
  return res.json(mapGridData);
};

export default {
  'GET  /api/tags': getTags,
  'GET  /api/monitor/map-geo': getMapGeo,
  'GET  /api/monitor/map-grid': getMapGrid,
};
