package httpsrv

import "context"

func (h *apiHandler) DeleteOAuthClient(ctx context.Context, request DeleteOAuthClientRequestObject) (DeleteOAuthClientResponseObject, error) {

	err := h.engine.DeleteOAuthClient(ctx, request.ClientID.String())
	if err != nil {
		return nil, err
	}
	return DeleteOAuthClient200JSONResponse{Success: true}, nil
}

func (h *apiHandler) GetOAuthClient(ctx context.Context, request GetOAuthClientRequestObject) (GetOAuthClientResponseObject, error) {
	return nil, nil
}

func (h *apiHandler) CreateOAuthClient(ctx context.Context, reqeust CreateOAuthClientRequestObject) (CreateOAuthClientResponseObject, error) {
	return nil, nil
}
