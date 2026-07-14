import { endpoint, obj, str } from '@bajustone/fortress';

export const endpoints = {
  getThing: endpoint('GET', '/things/:id')
    .params(obj({ id: str() }, 'id'))
    .response(200, 'OK', obj({ id: str() }, 'id'))
    .errorResponse(404, 'Not found')
    .handler('things.get')
    .build(),
} as const;
